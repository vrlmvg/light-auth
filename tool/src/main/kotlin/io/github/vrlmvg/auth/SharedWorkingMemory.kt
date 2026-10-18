package io.github.vrlmvg.auth

import android.os.SharedMemory
import java.nio.ByteBuffer

/**
 * Argon2 working memory backed by anonymous shared memory (memfd). Unlike direct buffers on
 * Android, it doesn't count against the app's ~192 MB Java heap limit, and it never touches storage.
 */
object SharedWorkingMemory : WorkingMemory {
    override fun <T> use(sizeBytes: Int, block: (ByteBuffer) -> T): T {
        val shared = try {
            SharedMemory.create("argon2", sizeBytes)
        } catch (e: Exception) {
            throw OutOfMemoryError("Could not reserve ${sizeBytes / (1024 * 1024)} MB: ${e.message}")
        }
        return shared.use { memory ->
            val buffer = memory.mapReadWrite()
            try {
                block(buffer)
            } finally {
                SharedMemory.unmap(buffer)
            }
        }
    }
}
