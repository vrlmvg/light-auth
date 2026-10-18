package io.github.vrlmvg.auth

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.lifecycle.viewModelScope
import com.thelightphone.sdk.LightFileShare
import com.thelightphone.sdk.LightScreen
import com.thelightphone.sdk.LightViewModel
import com.thelightphone.sdk.SealedLightActivity
import com.thelightphone.sdk.SimpleLightScreen
import com.thelightphone.sdk.rememberKeyboardOptions
import com.thelightphone.sdk.ui.LightBarButton
import com.thelightphone.sdk.ui.LightBottomBar
import com.thelightphone.sdk.ui.LightFullscreenModal
import com.thelightphone.sdk.ui.LightIcons
import com.thelightphone.sdk.ui.LightProgressBar
import com.thelightphone.sdk.ui.LightScrollView
import com.thelightphone.sdk.ui.LightText
import com.thelightphone.sdk.ui.LightTextInputEditor
import com.thelightphone.sdk.ui.LightTextVariant
import com.thelightphone.sdk.ui.LightTheme
import com.thelightphone.sdk.ui.LightThemeController
import com.thelightphone.sdk.ui.LightThemeTokens
import com.thelightphone.sdk.ui.LightTopBar
import com.thelightphone.sdk.ui.LightTopBarCenter
import com.thelightphone.sdk.ui.gridUnitsAsDp
import com.thelightphone.sdk.ui.lightClickable
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface ImportStep {
    data object Looking : ImportStep
    data object NoFile : ImportStep
    data class ChooseFile(val names: List<String>) : ImportStep
    data class Password(val fileName: String, val source: ImportSource.Encrypted) : ImportStep
    data class Unlocking(val progress: Float) : ImportStep
    data class Confirm(val fileName: String, val result: ImportResult, val duplicates: Int) : ImportStep
    data class Done(val imported: Int) : ImportStep
}

data class ImportState(
    val step: ImportStep = ImportStep.Looking,
    val passwordSession: Int = 0,
    val error: String? = null,
)

class ImportViewModel(
    private val fileShare: LightFileShare,
    private val repository: TotpAccountRepository,
) : LightViewModel<Unit>() {
    private val _state = MutableStateFlow(ImportState())
    val state: StateFlow<ImportState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            // Re-check the folder whenever the Tool Manager changes it while this screen is open.
            ToolEntryPoint.importFolderChanged.collect {
                val step = _state.value.step
                if (step is ImportStep.Looking || step is ImportStep.NoFile) lookForFiles()
            }
        }
    }

    fun lookForFiles() {
        viewModelScope.launch {
            val names = withContext(Dispatchers.IO) {
                fileShare.list(IMPORT_DIR).filter { it.isFile }.sortedByDescending { it.lastModified }.map { it.name }
            }
            when (names.size) {
                0 -> setStep(ImportStep.NoFile)
                1 -> open(names.single())
                else -> setStep(ImportStep.ChooseFile(names))
            }
        }
    }

    fun open(fileName: String) {
        viewModelScope.launch {
            val source = runCatching {
                withContext(Dispatchers.IO) {
                    val content = fileShare.read("$IMPORT_DIR/$fileName") { it.readText() }
                        ?: throw UnrecognisedImportFileException()
                    EnteImport.detect(content)
                }
            }.getOrElse { return@launch showError(it.message ?: "Could not read $fileName.") }

            when (source) {
                is ImportSource.PlainText -> prepare(fileName, source.text)
                is ImportSource.Encrypted -> _state.update {
                    it.copy(step = ImportStep.Password(fileName, source), passwordSession = it.passwordSession + 1)
                }
            }
        }
    }

    fun unlock(password: CharSequence) {
        val step = _state.value.step as? ImportStep.Password ?: return
        if (password.isEmpty()) return
        setStep(ImportStep.Unlocking(0f))
        viewModelScope.launch {
            val result = runCatching {
                withContext(Dispatchers.Default) {
                    EnteImport.decrypt(step.source, password.toString(), SharedWorkingMemory) { progress ->
                        _state.update { s ->
                            if (s.step is ImportStep.Unlocking) s.copy(step = ImportStep.Unlocking(progress)) else s
                        }
                    }
                }
            }
            result.fold(
                onSuccess = { text -> prepare(step.fileName, text) },
                onFailure = { error ->
                    val message = when (error) {
                        is DecryptionFailedException -> "That password didn't unlock the export. Try again."
                        is OutOfMemoryError ->
                            "Not enough free memory to unlock this export (it needs ${step.source.memoryMiB} MB). " +
                                "Close other tools and try again, or export from Ente as plain text."
                        else -> "Could not unlock the export."
                    }
                    _state.update {
                        it.copy(step = step, passwordSession = it.passwordSession + 1, error = message)
                    }
                },
            )
        }
    }

    fun confirmImport() {
        val step = _state.value.step as? ImportStep.Confirm ?: return
        viewModelScope.launch {
            val imported = withContext(Dispatchers.IO) {
                val existing = existingKeys()
                val fresh = step.result.accounts.filterNot { it.key() in existing }.distinctBy { it.key() }
                fresh.forEach { repository.addAccount(it) }
                // The export holds every secret in a readable or crackable form; don't leave it behind.
                fileShare.delete("$IMPORT_DIR/${step.fileName}")
                fresh.size
            }
            setStep(ImportStep.Done(imported))
        }
    }

    fun discardFile() {
        val name = when (val step = _state.value.step) {
            is ImportStep.Confirm -> step.fileName
            is ImportStep.Password -> step.fileName
            else -> return
        }
        viewModelScope.launch {
            withContext(Dispatchers.IO) { fileShare.delete("$IMPORT_DIR/$name") }
            lookForFiles()
        }
    }

    /** Removes the export when there is nothing new in it, and finishes. */
    fun discardFileAndClose() {
        val step = _state.value.step as? ImportStep.Confirm ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) { fileShare.delete("$IMPORT_DIR/${step.fileName}") }
            setStep(ImportStep.Done(0))
        }
    }

    fun dismissError() = _state.update { it.copy(error = null) }

    override fun onBackPressed(): Boolean = _state.value.step is ImportStep.Unlocking

    private suspend fun prepare(fileName: String, text: String) {
        val result = EnteImport.parseCodes(text)
        if (result.accounts.isEmpty()) {
            showError("No TOTP codes were found in $fileName.")
            return
        }
        val existing = withContext(Dispatchers.IO) { existingKeys() }
        val duplicates = result.accounts.count { it.key() in existing }
        setStep(ImportStep.Confirm(fileName, result, duplicates))
    }

    private fun existingKeys(): Set<String> =
        repository.listAccounts().map { "${it.issuer.lowercase()}|${it.label.lowercase()}" }.toSet()

    private fun Account.key() = "${issuer.lowercase()}|${label.lowercase()}"

    private fun setStep(step: ImportStep) = _state.update { it.copy(step = step) }

    private fun showError(message: String) = _state.update { it.copy(step = ImportStep.NoFile, error = message) }
}

class ImportScreen(
    sealedActivity: SealedLightActivity,
    private val repository: TotpAccountRepository,
) : LightScreen<Unit, ImportViewModel>(sealedActivity) {

    override val viewModelClass: Class<ImportViewModel>
        get() = ImportViewModel::class.java

    override fun createViewModel() = ImportViewModel(lightContext.fileShare, repository)

    override fun willShow() {
        super.willShow()
        viewModel.lookForFiles()
    }

    @Composable
    override fun Content() {
        val themeColors by LightThemeController.colors.collectAsState()
        val state by viewModel.state.collectAsState()
        val passwordField = rememberTextFieldState("")
        val keyboardOptionsFlow = rememberKeyboardOptions()
        LaunchedEffect(state.passwordSession) { passwordField.clearText() }

        LightTheme(colors = themeColors) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(LightThemeTokens.colors.background),
            ) {
                when (val step = state.step) {
                    is ImportStep.Password -> LightTextInputEditor(
                        title = "Export password",
                        state = passwordField,
                        keyboardOptionsFlow = keyboardOptionsFlow,
                        onSubmit = viewModel::unlock,
                        onBack = { goBack() },
                        submitLabel = "UNLOCK",
                        singleLine = true,
                        editorKey = state.passwordSession,
                        modifier = Modifier.fillMaxSize(),
                    )
                    else -> Column(modifier = Modifier.fillMaxSize()) {
                        LightTopBar(
                            leftButton = if (step is ImportStep.Unlocking) null else LightBarButton.LightIcon(
                                icon = LightIcons.BACK,
                                onClick = { goBack() },
                                contentDescription = "Back",
                            ),
                            center = LightTopBarCenter.Text("Import from Ente"),
                            modifier = Modifier.padding(bottom = 1f.gridUnitsAsDp()),
                        )
                        StepContent(step)
                    }
                }

                state.error?.let { LightFullscreenModal(message = it, onClose = viewModel::dismissError) }
            }
        }
    }

    @Composable
    private fun ColumnScope.StepContent(step: ImportStep) {
        when (step) {
            ImportStep.Looking -> Message("Looking for an export…")
            ImportStep.NoFile -> {
                LightScrollView(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .padding(horizontal = 1f.gridUnitsAsDp()),
                ) {
                    Instruction("1", "In the Ente Auth app on your other device, open Settings → Data → Export codes.")
                    Instruction("2", "On a computer on the same Wi-Fi, open the Tool Manager from your Light Phone's Settings.")
                    Instruction("3", "Choose Ente Auth → Ente export and upload the file.")
                    Instruction("4", "Come back here. The import starts on its own.")
                }
                LightBottomBar(
                    listOf(LightBarButton.LightIcon(LightIcons.REFRESH, onClick = viewModel::lookForFiles, contentDescription = "Check again")),
                )
            }
            is ImportStep.ChooseFile -> LightScrollView(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(start = 1f.gridUnitsAsDp()),
            ) {
                step.names.forEach { name ->
                    LightText(
                        text = name,
                        variant = LightTextVariant.Copy,
                        modifier = Modifier
                            .fillMaxWidth()
                            .lightClickable { viewModel.open(name) }
                            .padding(bottom = 1.5f.gridUnitsAsDp()),
                    )
                }
            }
            is ImportStep.Unlocking -> Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(horizontal = 2f.gridUnitsAsDp()),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                LightText("Unlocking export…", variant = LightTextVariant.Copy, align = TextAlign.Center)
                Box(Modifier.padding(vertical = 1f.gridUnitsAsDp())) {
                    LightProgressBar(colors = LightThemeTokens.colors, progress = step.progress)
                }
                LightText(
                    "This takes a while: Ente protects exports with a deliberately slow password check.",
                    variant = LightTextVariant.Detail,
                    lighten = true,
                    align = TextAlign.Center,
                )
            }
            is ImportStep.Confirm -> {
                val newCount = step.result.accounts.size - step.duplicates
                Message(
                    buildString {
                        if (newCount == 0) {
                            append("Every code in ${step.fileName} is already in Ente Auth.")
                        } else {
                            append(if (newCount == 1) "Found 1 new code" else "Found $newCount new codes")
                            append(" in ${step.fileName}.")
                            if (step.duplicates > 0) append("\n\n${step.duplicates} already in Ente Auth.")
                        }
                        if (step.result.skipped > 0) append("\n${step.result.skipped} skipped (only TOTP codes are supported).")
                    },
                )
                LightBottomBar(
                    if (newCount == 0) {
                        listOf(LightBarButton.Text("REMOVE FILE", onClick = viewModel::discardFileAndClose))
                    } else {
                        listOf(
                            LightBarButton.LightIcon(LightIcons.TRASH, onClick = viewModel::discardFile, contentDescription = "Delete file without importing"),
                            LightBarButton.Text("IMPORT", onClick = viewModel::confirmImport),
                            null,
                        )
                    },
                )
            }
            is ImportStep.Done -> {
                Message(
                    when (step.imported) {
                        0 -> "Nothing new to import."
                        1 -> "Imported 1 code."
                        else -> "Imported ${step.imported} codes."
                    } +
                        "\n\nThe export file has been deleted from your phone.",
                )
                LightBottomBar(listOf(LightBarButton.LightIcon(LightIcons.ACCEPT, onClick = { goBack() }, contentDescription = "Done")))
            }
            is ImportStep.Password -> Unit
        }
    }

    @Composable
    private fun ColumnScope.Message(text: String) {
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(horizontal = 1f.gridUnitsAsDp()),
            contentAlignment = Alignment.Center,
        ) {
            LightText(text, variant = LightTextVariant.Copy, align = TextAlign.Center)
        }
    }

    @Composable
    private fun Instruction(number: String, text: String) {
        Column(modifier = Modifier.padding(bottom = 1.5f.gridUnitsAsDp())) {
            LightText(number, variant = LightTextVariant.Detail, lighten = true)
            LightText(text, variant = LightTextVariant.Copy)
        }
    }
}
