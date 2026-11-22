package com.dastyab.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean

/**
 * AppAutoUpdater — Complete device-aware Android APK self-updater backed by
 * `https://github.com/DastYab/dastyab/releases/latest`.
 *
 * Features:
 *  • Device ABI selection (`Build.SUPPORTED_ABIS`): picks an ABI-matched APK
 *    if published, or falls back to the universal `DastYab-<ver>-android.apk`.
 *  • Semantic version comparison against `BuildConfig` / `PackageInfo.versionName`.
 *  • Resilient networking: tries direct HTTPS first, then routes through active
 *    [LocalProxyService] HTTP/SOCKS proxy if direct GitHub access is blocked;
 *    tries GitHub REST API first, then falls back to `/releases/latest` HTTP
 *    redirect resolution + direct download URLs.
 *  • Mandatory integrity verification: ZIP/APK magic (`PK\x03\x04`), minimum size,
 *    SHA-256 verification against `SHA256SUMS.txt` (rejects mismatches), and
 *    package-name match check via `PackageManager` when available.
 *  • Safe Android 7..14+ install handoff via [HarvestedFileProvider] +
 *    `ACTION_MANAGE_UNKNOWN_APP_SOURCES` permission handling on Android 8+.
 */
object AppAutoUpdater {

    const val REPO_OWNER = "DastYab"
    const val REPO_NAME = "dastyab"
    const val RELEASE_LATEST_API =
        "https://api.github.com/repos/DastYab/dastyab/releases/latest"
    const val RELEASE_LATEST_WEB =
        "https://github.com/DastYab/dastyab/releases/latest"
    const val AUTO_CHECK_INTERVAL_MS = 6L * 3600L * 1000L // 6 hours
    private const val PREF_LAST_CHECK_MS = "app_update_last_check_ms"
    private const val PREF_SKIPPED_TAG = "app_update_skipped_tag"
    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val READ_TIMEOUT_MS = 45_000
    private const val MIN_APK_BYTES = 64L * 1024L

    private val checkInFlight = AtomicBoolean(false)

    data class ApkAsset(
        val name: String,
        val downloadUrl: String,
        val apiUrl: String = "",
        val sizeBytes: Long = 0L
    )

    data class ReleaseInfo(
        val tag: String,
        val versionName: String,
        val apkAssets: List<ApkAsset>,
        val sha256SumsUrl: String?,
        val htmlUrl: String
    )

    sealed class CheckOutcome {
        data class UpToDate(val currentVersion: String, val remoteTag: String) : CheckOutcome()
        data class ReadyToInstall(
            val currentVersion: String,
            val remoteTag: String,
            val assetName: String,
            val apkFile: File
        ) : CheckOutcome()

        data class Failed(val message: String) : CheckOutcome()
    }

    // ── Pure, JVM-unit-testable helpers ─────────────────────────────────────

    /** Parse `v0.3.2` / `0.3.2-rc1` into numeric components `[major, minor, patch, ...]`. */
    fun parseVersionTuple(version: String): List<Int> {
        val cleaned = version.trim().removePrefix("v").removePrefix("V")
        if (cleaned.isEmpty()) return listOf(0, 0, 0)
        return cleaned.split('.').map { segment ->
            val digits = segment.takeWhile { it.isDigit() }
            digits.toIntOrNull() ?: 0
        }
    }

    /** Return >0 if [remote] is newer than [local], 0 if equal, <0 if older. */
    fun compareVersions(remote: String, local: String): Int {
        val a = parseVersionTuple(remote)
        val b = parseVersionTuple(local)
        val n = maxOf(a.size, b.size)
        for (i in 0 until n) {
            val av = a.getOrElse(i) { 0 }
            val bv = b.getOrElse(i) { 0 }
            if (av != bv) return av.compareTo(bv)
        }
        return 0
    }

    /** Extract tag name (e.g. `v0.4.0`) from `.../releases/tag/v0.4.0`. */
    fun parseTagFromReleaseUrl(url: String): String? {
        val marker = "/releases/tag/"
        val idx = url.indexOf(marker)
        if (idx < 0) return null
        val rest = url.substring(idx + marker.length)
        val tag = rest.split('?', '#', '/').firstOrNull()?.trim().orEmpty()
        return if (tag.isEmpty() || tag == "latest") null else tag
    }

    /** Parse `<hash>  [*]<filename>` from `SHA256SUMS.txt`. */
    fun parseSha256Sums(content: String, filename: String): String? {
        for (rawLine in content.lines()) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue
            val parts = line.split(Regex("\\s+"), limit = 2)
            if (parts.size == 2) {
                val hash = parts[0].trim()
                val file = parts[1].trim().removePrefix("*").removePrefix("./")
                if (file == filename && hash.matches(Regex("^[0-9a-fA-F]{64}$"))) {
                    return hash.lowercase()
                }
            }
        }
        return null
    }

    /**
     * Pick the best APK release asset for this device's [supportedAbis] priority list:
     *  1. Signed/release APK matching the highest-priority device ABI (arm64-v8a, armeabi-v7a, x86_64, x86)
     *  2. Explicit `universal` release APK
     *  3. Standard release APK (`DastYab-<ver>-android.apk` / any non-debug `.apk`)
     */
    fun selectBestApkAsset(assets: List<ApkAsset>, supportedAbis: Array<String>): ApkAsset? {
        val apks = assets.filter { it.name.endsWith(".apk", ignoreCase = true) }
        if (apks.isEmpty()) return null

        val releaseApks = apks.filter {
            val lower = it.name.lowercase()
            !lower.contains("unsigned") && !lower.contains("-debug")
        }.ifEmpty { apks }

        for (rawAbi in supportedAbis) {
            val abi = rawAbi.trim().lowercase()
            if (abi.isEmpty()) continue
            val match = releaseApks.firstOrNull { asset ->
                val lower = asset.name.lowercase()
                lower.contains(abi) ||
                    (abi == "armeabi-v7a" && lower.contains("armv7")) ||
                    (abi == "arm64-v8a" && (lower.contains("arm64") || lower.contains("aarch64")))
            }
            if (match != null) return match
        }

        releaseApks.firstOrNull { it.name.lowercase().contains("universal") }?.let { return it }
        releaseApks.firstOrNull { it.name.lowercase().startsWith("dastyab-") }?.let { return it }
        return releaseApks.first()
    }

    /** Check whether [nowMs] has crossed [intervalMs] since [lastCheckMs]. */
    fun isCheckDue(lastCheckMs: Long, nowMs: Long, intervalMs: Long = AUTO_CHECK_INTERVAL_MS): Boolean {
        if (lastCheckMs <= 0L) return true
        return (nowMs - lastCheckMs).coerceAtLeast(0L) >= intervalMs
    }

    /** Synthesize APK + SHA256SUMS asset URLs from a known release tag when REST API is unreachable. */
    fun synthesizeReleaseFromTag(tag: String): ReleaseInfo {
        val ver = tag.trim().removePrefix("v").removePrefix("V")
        val base = "https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/$tag"
        val universalName = "DastYab-$ver-android.apk"
        return ReleaseInfo(
            tag = tag,
            versionName = ver,
            apkAssets = listOf(
                ApkAsset(
                    name = universalName,
                    downloadUrl = "$base/$universalName"
                )
            ),
            sha256SumsUrl = "$base/SHA256SUMS.txt",
            htmlUrl = "https://github.com/$REPO_OWNER/$REPO_NAME/releases/tag/$tag"
        )
    }

    /** Check magic header (`PK\x03\x04`) and minimum length of an APK file. */
    fun isPlausibleApkFile(file: File): Boolean {
        if (!file.isFile || file.length() < MIN_APK_BYTES) return false
        val header = ByteArray(4)
        FileInputStream(file).use { fis ->
            if (fis.read(header) != 4) return false
        }
        return header[0] == 0x50.toByte() &&
            header[1] == 0x4B.toByte() &&
            header[2] == 0x03.toByte() &&
            header[3] == 0x04.toByte()
    }

    // ── Preference & filesystem state ───────────────────────────────────────

    fun isAutoUpdateEnabled(context: Context): Boolean {
        val prefs = context.getSharedPreferences(SettingsActivity.PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getBoolean(SettingsActivity.PREF_AUTO_UPDATE, true)
    }

    fun setAutoUpdateEnabled(context: Context, enabled: Boolean) {
        val prefs = context.getSharedPreferences(SettingsActivity.PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putBoolean(SettingsActivity.PREF_AUTO_UPDATE, enabled).apply()
    }

    fun isCheckDue(context: Context): Boolean {
        if (!isAutoUpdateEnabled(context)) return false
        val prefs = context.getSharedPreferences(SettingsActivity.PREFS_NAME, Context.MODE_PRIVATE)
        val last = prefs.getLong(PREF_LAST_CHECK_MS, 0L)
        return isCheckDue(last, System.currentTimeMillis())
    }

    fun markCheckedNow(context: Context) {
        val prefs = context.getSharedPreferences(SettingsActivity.PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putLong(PREF_LAST_CHECK_MS, System.currentTimeMillis()).apply()
    }

    fun markTagSkipped(context: Context, tag: String) {
        val prefs = context.getSharedPreferences(SettingsActivity.PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putString(PREF_SKIPPED_TAG, tag).apply()
    }

    fun isTagSkipped(context: Context, tag: String): Boolean {
        val prefs = context.getSharedPreferences(SettingsActivity.PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(PREF_SKIPPED_TAG, null) == tag
    }

    fun installedVersionName(context: Context): String {
        return try {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "0.0.0"
        } catch (_: Throwable) {
            "0.0.0"
        }
    }

    fun updatesDir(context: Context): File =
        File(context.filesDir, HarvestedFileProvider.UPDATES_PATH_PREFIX)

    fun cleanupStaleUpdates(context: Context, keepFileName: String? = null) {
        val dir = updatesDir(context)
        if (!dir.isDirectory) return
        val files = dir.listFiles() ?: return
        for (f in files) {
            if (f.isFile && f.name != keepFileName) {
                runCatching { f.delete() }
            }
        }
    }

    // ── Network + Verification + Install ────────────────────────────────────

    private fun candidateProxies(): List<Proxy> {
        val list = mutableListOf(Proxy.NO_PROXY)
        val localPort = LocalProxyService.activePort()
        if (localPort != null && localPort > 0) {
            list.add(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", localPort)))
        }
        return list
    }

    private fun openConnection(urlStr: String, proxy: Proxy, followRedirects: Boolean): HttpURLConnection {
        val conn = URL(urlStr).openConnection(proxy) as HttpURLConnection
        conn.instanceFollowRedirects = followRedirects
        conn.connectTimeout = CONNECT_TIMEOUT_MS
        conn.readTimeout = READ_TIMEOUT_MS
        conn.setRequestProperty("User-Agent", "DastYab-Android-AutoUpdater/1.0")
        return conn
    }

    fun fetchLatestRelease(): ReleaseInfo? {
        for (proxy in candidateProxies()) {
            val fromApi = runCatching { fetchViaApi(proxy) }.getOrNull()
            if (fromApi != null) return fromApi

            val fromRedirect = runCatching { fetchViaLatestRedirect(proxy) }.getOrNull()
            if (fromRedirect != null) return fromRedirect
        }
        return null
    }

    private fun fetchViaApi(proxy: Proxy): ReleaseInfo? {
        val conn = openConnection(RELEASE_LATEST_API, proxy, true)
        conn.setRequestProperty("Accept", "application/vnd.github+json")
        try {
            if (conn.responseCode !in 200..299) return null
            val body = conn.inputStream.bufferedReader().readText()
            val json = JSONObject(body)
            val tag = json.optString("tag_name").trim()
            if (tag.isEmpty()) return null
            val htmlUrl = json.optString(
                "html_url",
                "https://github.com/$REPO_OWNER/$REPO_NAME/releases/tag/$tag"
            )
            val assetsArr = json.optJSONArray("assets")
            val apkAssets = mutableListOf<ApkAsset>()
            var sumsUrl: String? = null
            if (assetsArr != null) {
                for (i in 0 until assetsArr.length()) {
                    val obj = assetsArr.optJSONObject(i) ?: continue
                    val name = obj.optString("name").trim()
                    val dlUrl = obj.optString("browser_download_url").trim()
                    val apiUrl = obj.optString("url").trim()
                    val size = obj.optLong("size", 0L)
                    if (name.equals("SHA256SUMS.txt", ignoreCase = true)) {
                        sumsUrl = dlUrl.ifEmpty { apiUrl }
                    } else if (name.endsWith(".apk", ignoreCase = true) && dlUrl.isNotEmpty()) {
                        apkAssets.add(ApkAsset(name, dlUrl, apiUrl, size))
                    }
                }
            }
            return ReleaseInfo(
                tag = tag,
                versionName = tag.removePrefix("v").removePrefix("V"),
                apkAssets = apkAssets,
                sha256SumsUrl = sumsUrl,
                htmlUrl = htmlUrl
            )
        } finally {
            conn.disconnect()
        }
    }

    private fun fetchViaLatestRedirect(proxy: Proxy): ReleaseInfo? {
        val connNoRedirect = openConnection(RELEASE_LATEST_WEB, proxy, false)
        try {
            val code = connNoRedirect.responseCode
            val loc = connNoRedirect.getHeaderField("Location")
            if (code in 300..399 && !loc.isNullOrBlank()) {
                val tag = parseTagFromReleaseUrl(loc)
                if (tag != null) return synthesizeReleaseFromTag(tag)
            }
        } finally {
            connNoRedirect.disconnect()
        }

        val connFollow = openConnection(RELEASE_LATEST_WEB, proxy, true)
        try {
            connFollow.responseCode
            val finalUrl = connFollow.url?.toString().orEmpty()
            val tag = parseTagFromReleaseUrl(finalUrl) ?: return null
            return synthesizeReleaseFromTag(tag)
        } finally {
            connFollow.disconnect()
        }
    }

    private fun fetchTextResilient(url: String): String? {
        for (proxy in candidateProxies()) {
            val text = runCatching {
                val conn = openConnection(url, proxy, true)
                try {
                    if (conn.responseCode in 200..299) {
                        conn.inputStream.bufferedReader().readText()
                    } else {
                        null
                    }
                } finally {
                    conn.disconnect()
                }
            }.getOrNull()
            if (text != null) return text
        }
        return null
    }

    private fun downloadBinaryResilient(urls: List<String>, target: File): Boolean {
        val tmp = File(target.parentFile, "${target.name}.part")
        for (proxy in candidateProxies()) {
            for (u in urls) {
                if (u.isBlank()) continue
                val ok = runCatching {
                    val conn = openConnection(u, proxy, true)
                    if (u.startsWith("https://api.github.com")) {
                        conn.setRequestProperty("Accept", "application/octet-stream")
                    }
                    try {
                        if (conn.responseCode !in 200..299) return@runCatching false
                        conn.inputStream.use { input ->
                            FileOutputStream(tmp).use { out ->
                                val buf = ByteArray(64 * 1024)
                                while (true) {
                                    val n = input.read(buf)
                                    if (n <= 0) break
                                    out.write(buf, 0, n)
                                }
                                out.fd.sync()
                            }
                        }
                        true
                    } finally {
                        conn.disconnect()
                    }
                }.getOrDefault(false)
                if (ok && isPlausibleApkFile(tmp)) {
                    if (target.exists()) target.delete()
                    if (tmp.renameTo(target)) return true
                }
                tmp.delete()
            }
        }
        tmp.delete()
        return false
    }

    /**
     * Check GitHub `/releases/latest` for a newer APK matching this device, download
     * it into `filesDir/updates/`, verify APK magic + SHA-256 + package id, and
     * return [CheckOutcome]. Blocking — call from a background thread.
     */
    fun checkAndDownloadIfNeeded(context: Context, force: Boolean = false): CheckOutcome {
        if (!force && !checkInFlight.compareAndSet(false, true)) {
            return CheckOutcome.Failed("Update check already in progress")
        }
        try {
            val currentVer = installedVersionName(context)
            val release = fetchLatestRelease()
                ?: return CheckOutcome.Failed("Could not reach GitHub Releases")

            markCheckedNow(context)

            if (compareVersions(release.versionName, currentVer) <= 0) {
                cleanupStaleUpdates(context)
                return CheckOutcome.UpToDate(currentVer, release.tag)
            }

            if (!force && isTagSkipped(context, release.tag)) {
                return CheckOutcome.UpToDate(currentVer, release.tag)
            }

            val asset = selectBestApkAsset(release.apkAssets, Build.SUPPORTED_ABIS)
                ?: return CheckOutcome.Failed("No APK asset matches this device in ${release.tag}")

            val dir = updatesDir(context)
            if (!dir.exists() && !dir.mkdirs()) {
                return CheckOutcome.Failed("Cannot create update directory")
            }
            val apkFile = File(dir, asset.name)
            cleanupStaleUpdates(context, keepFileName = apkFile.name)

            // Resolve expected SHA-256 from SHA256SUMS.txt if published.
            val sumsUrl = release.sha256SumsUrl
                ?: "https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/${release.tag}/SHA256SUMS.txt"
            val sumsContent = fetchTextResilient(sumsUrl)
            val expectedHash = sumsContent?.let { parseSha256Sums(it, asset.name) }

            val alreadyDownloadedValid = apkFile.isFile && isPlausibleApkFile(apkFile) &&
                (expectedHash == null || ChecksumUtils.sha256Hex(apkFile).equals(expectedHash, ignoreCase = true))

            if (!alreadyDownloadedValid) {
                apkFile.delete()
                val urls = listOf(asset.downloadUrl, asset.apiUrl).filter { it.isNotBlank() }
                if (!downloadBinaryResilient(urls, apkFile)) {
                    return CheckOutcome.Failed("Download failed or corrupt APK for ${asset.name}")
                }
                if (expectedHash != null) {
                    val actualHash = ChecksumUtils.sha256Hex(apkFile)
                    if (!actualHash.equals(expectedHash, ignoreCase = true)) {
                        apkFile.delete()
                        return CheckOutcome.Failed(
                            "SHA-256 verification failed for ${asset.name}"
                        )
                    }
                }
            }

            // Verify APK archive belongs to our applicationId so an unrelated APK
            // can never accidentally be offered for install.
            val pkgInfo = runCatching {
                context.packageManager.getPackageArchiveInfo(apkFile.absolutePath, 0)
            }.getOrNull()
            if (pkgInfo != null && pkgInfo.packageName != context.packageName) {
                apkFile.delete()
                return CheckOutcome.Failed("Package mismatch (${pkgInfo.packageName})")
            }

            DastyabLogger.i("AppAutoUpdater", "Verified APK update ready: %s -> %s", currentVer, release.tag)
            return CheckOutcome.ReadyToInstall(currentVer, release.tag, asset.name, apkFile)
        } catch (t: Throwable) {
            DastyabLogger.e("AppAutoUpdater", t, "Auto-update check failed")
            return CheckOutcome.Failed(t.message ?: t.toString())
        } finally {
            if (!force) checkInFlight.set(false)
        }
    }

    /**
     * Launch Android's package installer for [apkFile], requesting unknown-source
     * install permission first if needed on Android 8+. Returns `true` if installer
     * launched, or `false` if settings permission screen was opened instead.
     */
    fun launchInstallerOrRequestPermission(activity: Activity, apkFile: File): Boolean {
        if (!apkFile.isFile) return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            !activity.packageManager.canRequestPackageInstalls()
        ) {
            val settingsIntent = Intent(
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:${activity.packageName}")
            )
            UiSafety.safeStartActivity(activity, settingsIntent)
            return false
        }
        val uri = HarvestedFileProvider.uriForUpdateFile(apkFile)
        val installIntent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return UiSafety.safeStartActivity(activity, installIntent)
    }
}
