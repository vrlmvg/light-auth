package io.github.vrlmvg.auth

import com.thelightphone.sdk.EntryPoint
import com.thelightphone.sdk.LightEntryPoint
import com.thelightphone.toolmanager.ClientLeafNode
import com.thelightphone.toolmanager.ClientToolManifest
import com.thelightphone.toolmanager.FileBrowserSpec
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Folder (inside the tool's shared files) that the Tool Manager uploads Ente exports into. */
internal const val IMPORT_DIR = "import"

@EntryPoint
object ToolEntryPoint : LightEntryPoint {
    private val _importFolderChanged = MutableStateFlow(0L)

    /** Ticks whenever files are uploaded or removed through the Tool Manager. */
    val importFolderChanged: StateFlow<Long> = _importFolderChanged.asStateFlow()

    override fun getToolManagerManifest(): ClientToolManifest = ClientToolManifest(
        title = "Ente Auth",
        roots = listOf(
            ClientLeafNode(
                FileBrowserSpec(
                    label = "Ente export",
                    path = IMPORT_DIR,
                    headerText = "Upload an Ente Auth export (plain text or encrypted), then open " +
                        "Ente Auth on your Light Phone and choose IMPORT. The file is deleted from " +
                        "the phone once it has been imported.",
                ),
            ),
        ),
    )

    override suspend fun onToolManagerDataUpdate() {
        super.onToolManagerDataUpdate()
        _importFolderChanged.value = System.currentTimeMillis()
    }
}
