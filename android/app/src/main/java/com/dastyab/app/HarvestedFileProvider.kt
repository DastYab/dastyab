package com.dastyab.app

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.File
import java.io.FileNotFoundException

/**
 * Self-contained read-only [ContentProvider] serving:
 *  • Downloaded VPN config files under `filesDir/vault/`
 *  • Verified APK self-update installers under `filesDir/updates/` (`.../updates/<apk>`)
 * with accurate display names & sizes so external VPN apps and Android's PackageInstaller
 * can open them cleanly via `content://com.dastyab.app.filevault/...`.
 */
class HarvestedFileProvider : ContentProvider() {

    companion object {
        const val AUTHORITY = "com.dastyab.app.filevault"
        const val UPDATES_PATH_PREFIX = "updates"
        private const val APK_MIME = "application/vnd.android.package-archive"

        fun uriForFile(file: File): Uri {
            return Uri.Builder()
                .scheme("content")
                .authority(AUTHORITY)
                .appendPath(file.name)
                .build()
        }

        fun uriForUpdateFile(file: File): Uri {
            return Uri.Builder()
                .scheme("content")
                .authority(AUTHORITY)
                .appendPath(UPDATES_PATH_PREFIX)
                .appendPath(file.name)
                .build()
        }
    }

    override fun onCreate(): Boolean = true

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? {
        val file = resolveFile(uri) ?: return null
        val cols = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        val cursor = MatrixCursor(cols, 1)
        val row = Array<Any?>(cols.size) { idx ->
            when (cols[idx]) {
                OpenableColumns.DISPLAY_NAME -> file.name
                OpenableColumns.SIZE -> file.length()
                else -> null
            }
        }
        cursor.addRow(row)
        return cursor
    }

    override fun getType(uri: Uri): String {
        val segments = uri.pathSegments
        if (segments.firstOrNull() == UPDATES_PATH_PREFIX ||
            uri.lastPathSegment?.lowercase()?.endsWith(".apk") == true
        ) {
            return APK_MIME
        }
        val ext = uri.lastPathSegment?.substringAfterLast('.', "")?.lowercase().orEmpty()
        return ConfigFileHarvester.mimeTypeForExtension(ext)
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        val file = resolveFile(uri) ?: throw FileNotFoundException("Vault file not found: $uri")
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0

    private fun resolveFile(uri: Uri): File? {
        val ctx = context ?: return null
        val segments = uri.pathSegments
        val (baseDir, fileName) = when {
            segments.size == 2 && segments[0] == UPDATES_PATH_PREFIX -> {
                File(ctx.filesDir, UPDATES_PATH_PREFIX) to segments[1].trim()
            }
            segments.size == 1 -> {
                File(ctx.filesDir, ConfigFileHarvester.VAULT_DIR_NAME) to segments[0].trim()
            }
            else -> return null
        }
        if (fileName.isEmpty() || fileName.contains("..") || fileName.contains('/') || fileName.contains('\\')) {
            return null
        }
        val candidate = File(baseDir, fileName)
        if (!candidate.isFile) return null
        val canonicalBase = runCatching { baseDir.canonicalPath }.getOrNull() ?: return null
        val canonicalFile = runCatching { candidate.canonicalPath }.getOrNull() ?: return null
        return if (canonicalFile.startsWith("$canonicalBase/")) candidate else null
    }
}
