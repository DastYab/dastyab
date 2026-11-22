package com.dastyab.app

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.provider.OpenableColumns
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * ConfigFileHarvester — harvests, downloads, stores, and inspects VPN configuration files
 * of ANY extension across Telegram channels, GitHub feeds, direct URLs, and local storage:
 *
 *  • OpenVPN: `.ovpn`, `.openvpn`
 *  • NapsternetV: `.npvs`, `.npv4`, `.npv`, `.npvt`
 *  • HTTP Custom / Injector / SocksHTTP / DarkTunnel / HA Tunnel / TLS Tunnel / NetMod:
 *    `.hc`, `.custom`, `.costum`, `.ehi`, `.dark`, `.hat`, `.tls`, `.nm`, `.sks`, `.sip`, `.inp`
 *  • WireGuard / WARP / AmneziaWG: `.conf`, `.wg`
 *  • Xray / Sing-box / Clash / Subscriptions: `.json`, `.yaml`, `.yml`, `.sub`, `.txt`
 *
 * All parsing, URL/attachment extraction, extension classification, and JSON vault serialization
 * are pure Kotlin (unit-testable on the plain JVM without Android stubs).
 */
object ConfigFileHarvester {

    const val VAULT_DIR_NAME = "vpn_vault"
    private const val PREFS_NAME = "dastyab_file_vault"
    private const val KEY_VAULT_JSON = "vault_entries_v1"
    private const val MAX_FILE_BYTES = 8 * 1024 * 1024 // 8 MB cap per config file
    private const val MAX_VAULT_ENTRIES = 250

    val BINARY_OR_IMPORT_EXTENSIONS = setOf(
        "ovpn", "openvpn", "ovpn2", "npvs", "npv4", "npv", "npvt",
        "hc", "ehi", "custom", "costum", "dark", "hat", "tls", "nm",
        "sks", "sip", "inp", "conf", "wg", "awg", "amneziawg", "warp",
        "sbox", "singbox", "clash", "mihomo", "nekobox", "hiddify",
        "xray", "v2ray", "prox", "rules", "tunnels", "vpn", "profile",
        "sub", "b64", "base64"
    )

    val STRUCTURED_TEXT_EXTENSIONS = setOf(
        "ovpn", "openvpn", "ovpn2", "conf", "wg", "awg", "amneziawg", "warp",
        "json", "jsonc", "yaml", "yml", "sub", "txt",
        "list", "links", "urls", "nodes", "servers", "proxies",
        "ini", "cfg", "sbox", "singbox", "clash", "mihomo", "nekobox",
        "hiddify", "xray", "v2ray", "prox", "rules", "tunnels", "vpn",
        "profile", "toml", "b64", "base64"
    )

    val NOISE_CONFIG_FILENAMES = setOf(
        "robots.txt", "ads.txt", "humans.txt", "security.txt",
        "license.txt", "changelog.txt", "readme.txt"
    )

    val ALL_CONFIG_EXTENSIONS = BINARY_OR_IMPORT_EXTENSIONS + STRUCTURED_TEXT_EXTENSIONS

    data class DiscoveredFile(
        val fileName: String,
        val extension: String,
        val downloadUrl: String?,
        val postUrl: String?,
        val sourceLabel: String,
        val sizeLabel: String = ""
    )

    data class VaultEntry(
        val id: String,
        val fileName: String,
        val extension: String,
        val localPath: String,
        val sourceLabel: String,
        val downloadUrl: String?,
        val postUrl: String?,
        val sizeBytes: Long,
        val extractedEndpoints: Int,
        val createdAtMs: Long
    ) {
        val isDownloadedLocally: Boolean get() = localPath.isNotBlank() && File(localPath).isFile

        fun label(): String = when {
            isDownloadedLocally -> "[.${extension.uppercase()}] $fileName (${formatSize(sizeBytes)}) · $sourceLabel"
            else -> "[.${extension.uppercase()} · TG] $fileName · $sourceLabel"
        }
    }

    private val FILE_URL_REGEX = Regex(
        """https?://[^\s"'<>`\\)]+""",
        RegexOption.IGNORE_CASE
    )

    private val HREF_OR_SRC_REGEX = Regex(
        """(?:href|src|data-href|data-url)\s*=\s*["']([^"']+)["']""",
        RegexOption.IGNORE_CASE
    )

    private val DOC_TITLE_REGEX = Regex(
        """<div[^>]*class="[^"]*tgme_widget_message_document_title[^"]*"[^>]*>(.*?)</div>""",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)
    )

    private val DOC_EXTRA_REGEX = Regex(
        """<div[^>]*class="[^"]*tgme_widget_message_document_extra[^"]*"[^>]*>(.*?)</div>""",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)
    )

    private val DATA_POST_REGEX = Regex("""data-post="([^"]+)"""")

    /** Extracts downloadable VPN config file URLs and Telegram channel document attachments from HTML or text. */
    fun extractChannelFiles(
        rawBody: String,
        sourceLabel: String,
        baseUrl: String = "https://t.me"
    ): List<DiscoveredFile> {
        if (rawBody.isBlank()) return emptyList()
        val unescaped = rawBody
            .replace("&amp;", "&")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")

        val results = LinkedHashMap<String, DiscoveredFile>()

        fun addCandidateUrl(rawUrl: String) {
            val clean = rawUrl.trim().trimEnd(',', ';', '.', ')', ']', '}')
            if (!clean.startsWith("http://", ignoreCase = true) &&
                !clean.startsWith("https://", ignoreCase = true)
            ) return
            val pathPart = clean.substringBefore('?').substringBefore('#')
            val fileName = sanitizeFileName(pathPart.substringAfterLast('/', ""))
            val ext = fileName.substringAfterLast('.', "").lowercase()
            if (ext !in ALL_CONFIG_EXTENSIONS) return
            // Only skip standard site metadata `.txt` files (never drop Telegram/CDN server list `.txt` drops!)
            if (ext == "txt" && fileName.lowercase() in NOISE_CONFIG_FILENAMES) return
            val key = clean.lowercase()
            if (!results.containsKey(key)) {
                results[key] = DiscoveredFile(
                    fileName = fileName.ifBlank { "config.$ext" },
                    extension = ext,
                    downloadUrl = clean,
                    postUrl = null,
                    sourceLabel = sourceLabel
                )
            }
        }

        // 1. Direct URLs in plain text / markdown / JSON / Telegram messages
        FILE_URL_REGEX.findAll(unescaped).forEach { addCandidateUrl(it.value) }

        // 2. HTML attributes (href / src / data-href)
        HREF_OR_SRC_REGEX.findAll(unescaped).forEach { m ->
            val candidate = m.groupValues[1].trim()
            val resolved = when {
                candidate.startsWith("http://", true) || candidate.startsWith("https://", true) -> candidate
                candidate.startsWith("//") -> "https:$candidate"
                candidate.startsWith("/") -> baseUrl.trimEnd('/') + candidate
                else -> ""
            }
            if (resolved.isNotEmpty()) addCandidateUrl(resolved)
        }

        // 3. Telegram document attachments (`tgme_widget_message_wrap` with document title + data-post)
        val marker = "tgme_widget_message_wrap"
        val blocks = unescaped.split(marker)
        if (blocks.size > 1) {
            for (i in 1 until blocks.size) {
                val block = blocks[i]
                val docTitleRaw = DOC_TITLE_REGEX.find(block)?.groupValues?.getOrNull(1) ?: continue
                val title = stripHtmlTags(docTitleRaw).trim()
                val ext = title.substringAfterLast('.', "").lowercase()
                if (ext !in ALL_CONFIG_EXTENSIONS) continue

                val extra = DOC_EXTRA_REGEX.find(block)?.groupValues?.getOrNull(1)?.let { stripHtmlTags(it).trim() }.orEmpty()
                val dataPost = DATA_POST_REGEX.find(block)?.groupValues?.getOrNull(1)?.trim().orEmpty()
                val postUrl = if (dataPost.contains('/')) {
                    "https://t.me/${dataPost.trimStart('/')}"
                } else null

                // Check if block itself also carries a direct CDN file URL
                val directInBlock = HREF_OR_SRC_REGEX.findAll(block)
                    .map { it.groupValues[1].trim() }
                    .firstOrNull { href ->
                        val p = href.substringBefore('?').lowercase()
                        ALL_CONFIG_EXTENSIONS.any { e -> p.endsWith(".$e") }
                    }

                val key = "${title.lowercase()}::${postUrl ?: directInBlock ?: sourceLabel}"
                if (!results.containsKey(key)) {
                    results[key] = DiscoveredFile(
                        fileName = sanitizeFileName(title),
                        extension = ext,
                        downloadUrl = directInBlock,
                        postUrl = postUrl,
                        sourceLabel = sourceLabel,
                        sizeLabel = extra
                    )
                }
            }
        }

        return results.values.toList()
    }

    /**
     * Parses textual downloaded or local VPN config files (`.txt`, `.ovpn`, `.conf`, `.json`, `.yaml`, `.sub`, etc.)
     * using [UniversalConfig.extractAll] (which handles 619+ node `.txt` drops, multi-round Base64, Clash YAML,
     * Sing-Box/Xray/VMess JSON, WireGuard INI, OpenVPN, and explicit HTTP proxies while filtering web URLs).
     */
    fun extractEndpointsFromFileText(fileName: String, content: String): List<String> {
        if (content.isBlank()) return emptyList()
        val found = LinkedHashSet<String>()
        found.addAll(UniversalConfig.extractAll(content, maxConfigs = 4096))

        // Also capture OpenVPN `http-proxy` / `socks-proxy` directives even if block lacks `client`
        if (content.contains("http-proxy ", ignoreCase = true) || content.contains("socks-proxy ", ignoreCase = true)) {
            for (rawLine in content.lineSequence()) {
                val clean = rawLine.substringBefore('#').substringBefore(';').trim()
                val parts = clean.split(Regex("\\s+"))
                if (parts.size >= 3 && (parts[0].equals("http-proxy", true) || parts[0].equals("socks-proxy", true))) {
                    val port = parts[2].toIntOrNull()?.takeIf { it in 1..65535 } ?: continue
                    val scheme = if (parts[0].equals("socks-proxy", true)) "socks5" else "http"
                    val uri = "$scheme://${parts[1]}:$port"
                    if (UniversalConfig.parse(uri) != null) found.add(uri)
                }
            }
        }
        return found.toList()
    }

    /** Decodes UTF-8 / UTF-16LE / UTF-16BE bytes and merges any printable ASCII runs from binary containers. */
    fun decodeConfigBytes(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val decoded = when {
            bytes.size >= 3 && (bytes[0].toInt() and 0xFF) == 0xEF &&
                (bytes[1].toInt() and 0xFF) == 0xBB && (bytes[2].toInt() and 0xFF) == 0xBF ->
                String(bytes, 3, bytes.size - 3, Charsets.UTF_8)
            bytes.size >= 2 && (bytes[0].toInt() and 0xFF) == 0xFF &&
                (bytes[1].toInt() and 0xFF) == 0xFE ->
                String(bytes, 2, bytes.size - 2, Charsets.UTF_16LE)
            bytes.size >= 2 && (bytes[0].toInt() and 0xFF) == 0xFE &&
                (bytes[1].toInt() and 0xFF) == 0xFF ->
                String(bytes, 2, bytes.size - 2, Charsets.UTF_16BE)
            else -> String(bytes, Charsets.UTF_8)
        }
        val printable = buildString {
            val run = StringBuilder()
            for (b in bytes) {
                val u = b.toInt() and 0xFF
                if (u in 32..126 || u == 9 || u == 10 || u == 13) {
                    run.append(u.toChar())
                } else {
                    if (run.length >= 10) appendLine(run)
                    run.clear()
                }
            }
            if (run.length >= 10) appendLine(run)
        }
        return if (printable.length > decoded.length / 2) "$decoded\n$printable" else decoded
    }

    /** Convenience helper: extracts all config links straight from raw file bytes of any extension. */
    fun extractEndpointsFromFileBytes(fileName: String, bytes: ByteArray): List<String> {
        if (bytes.isEmpty()) return emptyList()
        return extractEndpointsFromFileText(fileName, decodeConfigBytes(bytes))
    }

    /**
     * Reads downloaded/imported `.txt` / `.npv*` / `.ovpn` / `.conf` / `.wg` / `.hc` / `.json` / `.yaml` /
     * `.sub` vault files on disk and extracts all chainable proxy hops for Lion & Warrior layering.
     */
    fun extractVaultHops(context: Context, maxFiles: Int = 40): List<TunnelConfig.ProxyHop> {
        val entries = loadVault(context)
        if (entries.isEmpty()) return emptyList()
        val uris = LinkedHashSet<String>()
        var filesRead = 0
        for (entry in entries) {
            if (filesRead >= maxFiles) break
            val p = entry.localPath.trim()
            if (p.isEmpty()) continue
            val f = File(p)
            if (!f.isFile || f.length() <= 0L || f.length() > MAX_FILE_BYTES) continue
            filesRead++
            val bytes = runCatching { f.readBytes() }.getOrNull() ?: continue
            uris.addAll(extractEndpointsFromFileBytes(entry.fileName, bytes))
        }
        return UniversalConfig.extractChainableProxyHops(uris.toList(), limit = 512)
    }

    fun mimeTypeForExtension(ext: String): String = when (ext.lowercase()) {
        "ovpn", "openvpn" -> "application/x-openvpn-profile"
        "conf", "wg" -> "text/plain"
        "json" -> "application/json"
        "yaml", "yml" -> "text/yaml"
        "txt", "sub" -> "text/plain"
        else -> "application/octet-stream"
    }

    fun recommendedAppsForExtension(ext: String): List<String> = when (ext.lowercase()) {
        "ovpn", "openvpn" -> listOf("OpenVPN for Android", "OpenVPN Connect", "Hiddify")
        "conf", "wg" -> listOf("WireGuard", "Hiddify", "NekoBox", "Cloudflare WARP")
        "npvs", "npv4", "npv", "npvt" -> listOf("NapsternetV", "Hiddify", "NekoBox")
        "hc" -> listOf("HTTP Custom")
        "ehi", "custom", "costum" -> listOf("HTTP Injector", "HTTP Custom")
        "dark" -> listOf("DarkTunnel")
        "hat" -> listOf("HA Tunnel Plus")
        "tls" -> listOf("TLS Tunnel")
        "nm" -> listOf("NetMod")
        else -> listOf("Hiddify", "NekoBox", "v2rayNG", "NapsternetV")
    }

    /** Harvests & downloads any reachable config files from channel/feed discoveries; returns extracted endpoints too. */
    fun harvestFilesFromBody(
        context: Context,
        rawBody: String,
        sourceLabel: String,
        maxDownloadsPerSource: Int = 5
    ): Pair<List<VaultEntry>, List<String>> {
        val discovered = extractChannelFiles(rawBody, sourceLabel)
        if (discovered.isEmpty()) return emptyList<VaultEntry>() to emptyList()

        val newOrUpdated = mutableListOf<VaultEntry>()
        val extractedUris = LinkedHashSet<String>()
        var downloadedCount = 0

        for (item in discovered) {
            var resolvedUrl = item.downloadUrl
            // If Telegram post attachment doesn't show direct CDN link in feed, check embed widget quickly
            if (resolvedUrl == null && item.postUrl != null && downloadedCount < maxDownloadsPerSource) {
                resolvedUrl = resolveTelegramEmbedFileUrl(item.postUrl)
            }
            if (resolvedUrl != null && downloadedCount < maxDownloadsPerSource) {
                val (entry, uris) = downloadAndStoreFile(
                    context = context,
                    urlStr = resolvedUrl,
                    fileNameHint = item.fileName,
                    sourceLabel = sourceLabel,
                    postUrl = item.postUrl
                )
                if (entry != null) {
                    newOrUpdated.add(entry)
                    extractedUris.addAll(uris)
                    downloadedCount++
                    continue
                }
            }
            // Store Telegram document attachment catalog entry so user can open the channel post directly
            if (item.postUrl != null) {
                val entry = VaultEntry(
                    id = "tgdoc-${(item.postUrl + item.fileName).hashCode().toUInt()}",
                    fileName = item.fileName,
                    extension = item.extension,
                    localPath = "",
                    sourceLabel = sourceLabel,
                    downloadUrl = resolvedUrl,
                    postUrl = item.postUrl,
                    sizeBytes = 0L,
                    extractedEndpoints = 0,
                    createdAtMs = System.currentTimeMillis()
                )
                upsertVaultEntry(context, entry)
                newOrUpdated.add(entry)
            }
        }
        return newOrUpdated to extractedUris.toList()
    }

    private fun resolveTelegramEmbedFileUrl(postUrl: String): String? {
        val embedUrl = "${postUrl.trimEnd('/')}?embed=1&mode=tme"
        val html = httpGetText(embedUrl, timeoutMs = 4000) ?: return null
        return extractChannelFiles(html, "telegram-embed").firstOrNull { it.downloadUrl != null }?.downloadUrl
    }

    /** Downloads a remote `.ovpn` / `.npvs` / `.hc` / `.custom` / `.conf` / `.json` config file into DastYab's vault. */
    fun downloadAndStoreFile(
        context: Context,
        urlStr: String,
        fileNameHint: String? = null,
        sourceLabel: String = "Direct URL",
        postUrl: String? = null
    ): Pair<VaultEntry?, List<String>> {
        val bytes = httpGetBytes(urlStr, timeoutMs = 6500) ?: return null to emptyList()
        val rawName = fileNameHint?.takeIf { it.isNotBlank() }
            ?: urlStr.substringBefore('?').substringBefore('#').substringAfterLast('/', "config.ovpn")
        val safeName = sanitizeFileName(rawName)
        val ext = safeName.substringAfterLast('.', "").lowercase()

        // Guard against HTML login/error pages pretending to be binary/text config files
        val prefix = String(bytes, 0, bytes.size.coerceAtMost(256), Charsets.UTF_8).trimStart()
        if (prefix.startsWith("<!DOCTYPE html", ignoreCase = true) ||
            prefix.startsWith("<html", ignoreCase = true)
        ) {
            return null to emptyList()
        }

        val extracted = extractEndpointsFromFileBytes(safeName, bytes)

        val vaultDir = File(context.filesDir, VAULT_DIR_NAME).apply { mkdirs() }
        val uniqueFile = File(vaultDir, makeUniqueName(vaultDir, safeName))
        uniqueFile.writeBytes(bytes)

        val entry = VaultEntry(
            id = "file-${uniqueFile.name.hashCode().toUInt()}-${System.currentTimeMillis() % 10000}",
            fileName = uniqueFile.name,
            extension = ext,
            localPath = uniqueFile.absolutePath,
            sourceLabel = sourceLabel,
            downloadUrl = urlStr,
            postUrl = postUrl,
            sizeBytes = bytes.size.toLong(),
            extractedEndpoints = extracted.size,
            createdAtMs = System.currentTimeMillis()
        )
        upsertVaultEntry(context, entry)
        return entry to extracted
    }

    /** Imports a user-selected file from Android Storage (`ACTION_OPEN_DOCUMENT` result URI) into the vault. */
    fun importLocalUri(context: Context, uri: Uri, sourceLabel: String = "Local Import"): Pair<VaultEntry?, List<String>> {
        val resolver = context.contentResolver
        val displayName = resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        } ?: uri.lastPathSegment?.substringAfterLast('/') ?: "imported.txt"

        val safeName = sanitizeFileName(displayName)
        val bytes = resolver.openInputStream(uri)?.use { it.readBytes() } ?: return null to emptyList()
        if (bytes.isEmpty() || bytes.size > MAX_FILE_BYTES) return null to emptyList()

        val ext = safeName.substringAfterLast('.', "").lowercase()
        val extracted = extractEndpointsFromFileBytes(safeName, bytes)

        val vaultDir = File(context.filesDir, VAULT_DIR_NAME).apply { mkdirs() }
        val uniqueFile = File(vaultDir, makeUniqueName(vaultDir, safeName))
        uniqueFile.writeBytes(bytes)

        val entry = VaultEntry(
            id = "local-${uniqueFile.name.hashCode().toUInt()}-${System.currentTimeMillis() % 10000}",
            fileName = uniqueFile.name,
            extension = ext,
            localPath = uniqueFile.absolutePath,
            sourceLabel = sourceLabel,
            downloadUrl = null,
            postUrl = null,
            sizeBytes = bytes.size.toLong(),
            extractedEndpoints = extracted.size,
            createdAtMs = System.currentTimeMillis()
        )
        upsertVaultEntry(context, entry)
        return entry to extracted
    }

    /** Writes a generated `.ovpn` or WireGuard `.conf` profile into the vault so external VPN apps can open it cleanly. */
    fun saveGeneratedTextFile(
        context: Context,
        fileName: String,
        content: String,
        sourceLabel: String = "Generated"
    ): VaultEntry {
        val safeName = sanitizeFileName(fileName)
        val ext = safeName.substringAfterLast('.', "txt").lowercase()
        val vaultDir = File(context.filesDir, VAULT_DIR_NAME).apply { mkdirs() }
        val outFile = File(vaultDir, makeUniqueName(vaultDir, safeName))
        val bytes = content.toByteArray(Charsets.UTF_8)
        outFile.writeBytes(bytes)

        val extracted = extractEndpointsFromFileText(safeName, content).size
        val entry = VaultEntry(
            id = "gen-${outFile.name.hashCode().toUInt()}-${System.currentTimeMillis() % 10000}",
            fileName = outFile.name,
            extension = ext,
            localPath = outFile.absolutePath,
            sourceLabel = sourceLabel,
            downloadUrl = null,
            postUrl = null,
            sizeBytes = bytes.size.toLong(),
            extractedEndpoints = extracted,
            createdAtMs = System.currentTimeMillis()
        )
        upsertVaultEntry(context, entry)
        return entry
    }

    fun loadVault(context: Context): List<VaultEntry> {
        val raw = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(KEY_VAULT_JSON, "") ?: ""
        return deserializeVault(raw)
    }

    fun clearVault(context: Context) {
        val vaultDir = File(context.filesDir, VAULT_DIR_NAME)
        vaultDir.listFiles()?.forEach { runCatching { it.delete() } }
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().remove(KEY_VAULT_JSON).apply()
    }

    fun openVaultFileInExternalApp(
        context: Context,
        entry: VaultEntry,
        targetPackage: String? = null
    ): Boolean {
        val file = File(entry.localPath)
        if (!file.isFile) return false
        val contentUri = HarvestedFileProvider.uriForFile(file)
        val mime = mimeTypeForExtension(entry.extension)
        val viewIntent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(contentUri, mime)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            if (!targetPackage.isNullOrBlank()) `package` = targetPackage
        }
        if (UiSafety.safeStartActivity(context, viewIntent)) return true

        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = mime
            putExtra(Intent.EXTRA_STREAM, contentUri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            if (!targetPackage.isNullOrBlank()) `package` = targetPackage
        }
        if (targetPackage != null && UiSafety.safeStartActivity(context, sendIntent)) return true
        return UiSafety.safeStartActivity(context, Intent.createChooser(sendIntent.apply { `package` = null }, entry.fileName))
    }

    fun exportToDownloads(context: Context, entry: VaultEntry): Boolean {
        val src = File(entry.localPath)
        if (!src.isFile) return false
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, entry.fileName)
                    put(MediaStore.Downloads.MIME_TYPE, mimeTypeForExtension(entry.extension))
                    put(MediaStore.Downloads.RELATIVE_PATH, "${Environment.DIRECTORY_DOWNLOADS}/DastYab")
                }
                val resolver = context.contentResolver
                val destUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: return false
                resolver.openOutputStream(destUri)?.use { out ->
                    src.inputStream().use { it.copyTo(out) }
                } ?: return false
                true
            } else {
                @Suppress("DEPRECATION")
                val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "DastYab").apply { mkdirs() }
                val dest = File(dir, entry.fileName)
                src.copyTo(dest, overwrite = true)
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun upsertVaultEntry(context: Context, entry: VaultEntry) {
        val current = loadVault(context).toMutableList()
        current.removeAll {
            it.id == entry.id ||
                (it.fileName.equals(entry.fileName, true) && it.postUrl == entry.postUrl && it.downloadUrl == entry.downloadUrl)
        }
        current.add(0, entry)
        val trimmed = current.take(MAX_VAULT_ENTRIES)
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_VAULT_JSON, serializeVault(trimmed))
            .apply()
    }

    /** Pure-Kotlin TSV/escaped-line vault serializer (unit-testable without org.json stubs). */
    fun serializeVault(entries: List<VaultEntry>): String {
        fun esc(s: String) = s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")
        return entries.joinToString("\n") { e ->
            listOf(
                esc(e.id),
                esc(e.fileName),
                esc(e.extension),
                esc(e.localPath),
                esc(e.sourceLabel),
                esc(e.downloadUrl.orEmpty()),
                esc(e.postUrl.orEmpty()),
                e.sizeBytes.toString(),
                e.extractedEndpoints.toString(),
                e.createdAtMs.toString()
            ).joinToString("\t")
        }
    }

    /** Pure-Kotlin vault deserializer. */
    fun deserializeVault(raw: String): List<VaultEntry> {
        if (raw.isBlank()) return emptyList()
        fun unesc(s: String): String {
            val sb = StringBuilder(s.length)
            var i = 0
            while (i < s.length) {
                if (s[i] == '\\' && i + 1 < s.length) {
                    when (s[i + 1]) {
                        't' -> { sb.append('\t'); i += 2; continue }
                        'n' -> { sb.append('\n'); i += 2; continue }
                        '\\' -> { sb.append('\\'); i += 2; continue }
                    }
                }
                sb.append(s[i])
                i++
            }
            return sb.toString()
        }
        return raw.lineSequence().mapNotNull { line ->
            val parts = line.split('\t')
            if (parts.size < 10) return@mapNotNull null
            VaultEntry(
                id = unesc(parts[0]),
                fileName = unesc(parts[1]),
                extension = unesc(parts[2]),
                localPath = unesc(parts[3]),
                sourceLabel = unesc(parts[4]),
                downloadUrl = unesc(parts[5]).takeIf { it.isNotEmpty() },
                postUrl = unesc(parts[6]).takeIf { it.isNotEmpty() },
                sizeBytes = parts[7].toLongOrNull() ?: 0L,
                extractedEndpoints = parts[8].toIntOrNull() ?: 0,
                createdAtMs = parts[9].toLongOrNull() ?: 0L
            )
        }.toList()
    }

    private fun makeUniqueName(dir: File, safeName: String): String {
        if (!File(dir, safeName).exists()) return safeName
        val base = safeName.substringBeforeLast('.')
        val ext = safeName.substringAfterLast('.', "")
        val suffix = System.currentTimeMillis() % 100_000
        return if (ext.isNotEmpty()) "${base}_$suffix.$ext" else "${base}_$suffix"
    }

    private fun sanitizeFileName(raw: String): String {
        val cleaned = raw.trim().replace(Regex("[^A-Za-z0-9._-]"), "_").trim('_')
        return if (cleaned.isBlank()) "config_${System.currentTimeMillis()}.conf" else cleaned.take(96)
    }

    private fun stripHtmlTags(raw: String): String =
        raw.replace(Regex("<[^>]+>"), " ").replace(Regex("\\s+"), " ").trim()

    private fun isMostlyText(bytes: ByteArray): Boolean {
        val sample = bytes.take(512)
        if (sample.isEmpty()) return false
        val bad = sample.count { b ->
            val u = b.toInt() and 0xFF
            u < 9 || (u in 14..31)
        }
        return bad <= sample.size / 20
    }

    private fun formatSize(bytes: Long): String = when {
        bytes <= 0 -> "ref"
        bytes < 1024 -> "${bytes}B"
        bytes < 1024 * 1024 -> "${bytes / 1024}KB"
        else -> String.format(java.util.Locale.US, "%.1fMB", bytes / (1024.0 * 1024.0))
    }

    private fun httpGetText(urlStr: String, timeoutMs: Int): String? {
        val bytes = httpGetBytes(urlStr, timeoutMs) ?: return null
        return String(bytes, Charsets.UTF_8)
    }

    private fun httpGetBytes(urlStr: String, timeoutMs: Int): ByteArray? {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                instanceFollowRedirects = true
                setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) DastYab/1.8")
            }
            if (conn.responseCode !in 200..299) return null
            conn.inputStream.use { input ->
                val out = ByteArrayOutputStream()
                val buf = ByteArray(8192)
                var total = 0
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    total += n
                    if (total > MAX_FILE_BYTES) return null
                    out.write(buf, 0, n)
                }
                out.toByteArray()
            }
        } catch (_: Exception) {
            null
        } finally {
            conn?.disconnect()
        }
    }
}
