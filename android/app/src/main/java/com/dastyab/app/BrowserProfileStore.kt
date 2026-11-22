package com.dastyab.app

import android.content.Context
import android.webkit.CookieManager
import android.webkit.WebStorage
import androidx.webkit.ProfileStore
import androidx.webkit.WebViewFeature
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.UUID

/**
 * BrowserProfileStore — Manages isolated Google Account browser profiles for [InAppBrowserActivity].
 *
 * Isolation Architecture:
 *  • Primary Tier (`WebViewFeature.MULTI_PROFILE` supported, Chromium >= 121):
 *    Binds each browser profile to its own Chromium `Profile` (`ProfileStore` + `WebViewCompat.setProfile`),
 *    keeping Google auth cookies, localStorage, IndexedDB, cache, and ServiceWorkers 100% separated.
 *    The built-in first profile uses `"Default"` (`Profile.DEFAULT_PROFILE_NAME`) so existing logged-in
 *    sessions survive seamlessly across app updates.
 *  • Universal Fallback Tier (older System WebView engines, API 24+):
 *    Snapshots and restores per-profile Google & site cookie jars to private app storage
 *    (`filesDir/browser_profiles/jar_<id>.txt`) and wipes volatile `CookieManager` / `WebStorage` on switch.
 */
object BrowserProfileStore {

    const val DEFAULT_PROFILE_ID = "default"
    const val DEFAULT_WEBKIT_PROFILE = "Default"
    const val GOOGLE_SIGNIN_CONTINUE_URL =
        "https://accounts.google.com/ServiceLogin?hl=en&continue=https%3A%2F%2Faistudio.google.com%2F"

    private const val DIR_NAME = "browser_profiles"
    private const val PROFILES_FILE = "profiles.json"

    val PROFILE_COLORS = listOf(
        "#E3BE4E", // Royal Gold
        "#38BDF8", // Sky Cyan
        "#34D399", // Emerald Mint
        "#FB7185", // Coral Rose
        "#A78BFA", // Amethyst Violet
        "#F59E0B", // Amber Glow
        "#2DD4BF", // Teal Tide
        "#F472B6"  // Orchid Pink
    )

    val GOOGLE_SESSION_ORIGINS = listOf(
        "https://accounts.google.com",
        "https://myaccount.google.com",
        "https://www.google.com",
        "https://google.com",
        "https://apis.google.com",
        "https://aistudio.google.com",
        "https://ai.google.dev",
        "https://labs.google",
        "https://flow.google.com"
    )

    data class BrowserProfile(
        val id: String,
        val name: String,
        val webkitName: String,
        val colorHex: String,
        val detectedEmail: String = "",
        val lastUrl: String = CommandCompat.AISTUDIO_URL,
        val desktopMode: Boolean = false,
        val createdAtMs: Long = 0L
    )

    data class BrowserProfileState(
        val activeProfileId: String,
        val profiles: List<BrowserProfile>
    ) {
        fun activeProfile(): BrowserProfile =
            profiles.firstOrNull { it.id == activeProfileId } ?: profiles.first()
    }

    data class DeleteResult(
        val state: BrowserProfileState,
        val removed: BrowserProfile?,
        val rejectedReason: String? = null
    )

    // ── Pure, JVM-unit-testable state & formatting helpers ──────────────────

    fun defaultState(initialUrl: String = CommandCompat.AISTUDIO_URL): BrowserProfileState {
        return BrowserProfileState(
            activeProfileId = DEFAULT_PROFILE_ID,
            profiles = listOf(
                BrowserProfile(
                    id = DEFAULT_PROFILE_ID,
                    name = "Account 1",
                    webkitName = DEFAULT_WEBKIT_PROFILE,
                    colorHex = PROFILE_COLORS.first(),
                    lastUrl = initialUrl,
                    createdAtMs = 1L
                )
            )
        )
    }

    fun selectNextColor(existing: List<BrowserProfile>): String {
        val used = existing.mapTo(HashSet()) { it.colorHex.uppercase(Locale.US) }
        return PROFILE_COLORS.firstOrNull { it.uppercase(Locale.US) !in used }
            ?: PROFILE_COLORS[existing.size % PROFILE_COLORS.size]
    }

    fun sanitizeProfileId(rawId: String): String {
        val cleaned = rawId.trim().lowercase(Locale.US).replace(Regex("[^a-z0-9_-]"), "_")
        return cleaned.ifEmpty { "p_${System.currentTimeMillis()}" }
    }

    fun webkitProfileNameFor(id: String): String {
        if (id == DEFAULT_PROFILE_ID) return DEFAULT_WEBKIT_PROFILE
        return "dastyab_${sanitizeProfileId(id)}"
    }

    fun createProfile(
        state: BrowserProfileState,
        rawName: String,
        colorHex: String? = null,
        initialUrl: String = CommandCompat.AISTUDIO_URL,
        nowMs: Long = System.currentTimeMillis()
    ): Pair<BrowserProfileState, BrowserProfile> {
        val trimmed = rawName.trim()
        val finalName = if (trimmed.isNotEmpty()) {
            trimmed.take(28)
        } else {
            "Account ${state.profiles.size + 1}"
        }
        val short = UUID.randomUUID().toString().replace("-", "").take(8)
        val id = "p_${state.profiles.size + 1}_$short"
        val profile = BrowserProfile(
            id = id,
            name = finalName,
            webkitName = webkitProfileNameFor(id),
            colorHex = colorHex?.takeIf { it.startsWith("#") } ?: selectNextColor(state.profiles),
            lastUrl = initialUrl,
            createdAtMs = nowMs
        )
        val next = BrowserProfileState(
            activeProfileId = profile.id,
            profiles = state.profiles + profile
        )
        return next to profile
    }

    fun switchProfile(state: BrowserProfileState, targetId: String): BrowserProfileState {
        if (state.profiles.none { it.id == targetId }) return state
        return state.copy(activeProfileId = targetId)
    }

    fun renameProfile(state: BrowserProfileState, id: String, rawName: String): BrowserProfileState {
        val clean = rawName.trim().take(28)
        if (clean.isEmpty()) return state
        return state.copy(
            profiles = state.profiles.map { p -> if (p.id == id) p.copy(name = clean) else p }
        )
    }

    fun updateColor(state: BrowserProfileState, id: String, colorHex: String): BrowserProfileState {
        if (!colorHex.matches(Regex("^#[0-9A-Fa-f]{6}$"))) return state
        return state.copy(
            profiles = state.profiles.map { p -> if (p.id == id) p.copy(colorHex = colorHex) else p }
        )
    }

    fun updateDetectedEmail(
        state: BrowserProfileState,
        id: String,
        rawEmail: String
    ): BrowserProfileState {
        val clean = rawEmail.trim()
        if (!clean.contains("@") || clean.length > 96) return state
        return state.copy(
            profiles = state.profiles.map { p ->
                if (p.id == id && p.detectedEmail != clean) p.copy(detectedEmail = clean) else p
            }
        )
    }

    fun updateLastUrl(state: BrowserProfileState, id: String, url: String): BrowserProfileState {
        if (!url.startsWith("http://") && !url.startsWith("https://")) return state
        return state.copy(
            profiles = state.profiles.map { p ->
                if (p.id == id) p.copy(lastUrl = url) else p
            }
        )
    }

    fun updateDesktopMode(
        state: BrowserProfileState,
        id: String,
        desktopMode: Boolean
    ): BrowserProfileState {
        return state.copy(
            profiles = state.profiles.map { p ->
                if (p.id == id) p.copy(desktopMode = desktopMode) else p
            }
        )
    }

    fun deleteProfile(state: BrowserProfileState, id: String): DeleteResult {
        if (state.profiles.size <= 1) {
            return DeleteResult(state, removed = null, rejectedReason = "At least one browser profile is required")
        }
        val idx = state.profiles.indexOfFirst { it.id == id }
        if (idx < 0) {
            return DeleteResult(state, removed = null, rejectedReason = "Profile not found")
        }
        val removed = state.profiles[idx]
        val remaining = state.profiles.filterNot { it.id == id }
        val nextActive = if (state.activeProfileId == id) {
            val fallbackIdx = idx.coerceAtMost(remaining.lastIndex)
            remaining[fallbackIdx].id
        } else {
            state.activeProfileId
        }
        return DeleteResult(
            state = BrowserProfileState(activeProfileId = nextActive, profiles = remaining),
            removed = removed
        )
    }

    fun avatarInitial(profile: BrowserProfile): String {
        val candidate = profile.detectedEmail.ifBlank { profile.name }.trim()
        val ch = candidate.firstOrNull { it.isLetterOrDigit() } ?: 'G'
        return ch.uppercaseChar().toString()
    }

    fun chipLabel(profile: BrowserProfile): String {
        val emailLocal = profile.detectedEmail.substringBefore('@').trim()
        return if (emailLocal.isNotBlank() && profile.name.startsWith("Account ")) {
            emailLocal.take(18)
        } else {
            profile.name.take(18)
        }
    }

    fun formatHostForOmnibar(url: String?): String {
        if (url.isNullOrBlank()) return "aistudio.google.com"
        return runCatching {
            val uri = URI(url)
            val host = uri.host?.removePrefix("www.").orEmpty()
            val path = uri.rawPath.orEmpty().takeIf { it != "/" && it.isNotBlank() }.orEmpty()
            if (host.isNotEmpty()) "$host$path".take(42) else url.take(42)
        }.getOrDefault(url.take(42))
    }

    private fun toHex(bytes: ByteArray): String {
        val hexChars = "0123456789abcdef"
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append(hexChars[v ushr 4])
            sb.append(hexChars[v and 0x0F])
        }
        return sb.toString()
    }

    private fun fromHex(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Odd hex length" }
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(hex[i * 2], 16)
            val lo = Character.digit(hex[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "Invalid hex char" }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    fun encodeCookieJarEntries(entries: Map<String, String>): String {
        return entries.entries
            .filter { it.key.isNotBlank() && it.value.isNotBlank() }
            .joinToString("\n") { (origin, cookie) ->
                val ok = toHex(origin.toByteArray(StandardCharsets.UTF_8))
                val ov = toHex(cookie.toByteArray(StandardCharsets.UTF_8))
                "$ok\t$ov"
            }
    }

    fun decodeCookieJarEntries(encoded: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (line in encoded.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue
            val tab = trimmed.indexOf('\t')
            if (tab <= 0) continue
            runCatching {
                val k = String(fromHex(trimmed.substring(0, tab)), StandardCharsets.UTF_8)
                val v = String(fromHex(trimmed.substring(tab + 1)), StandardCharsets.UTF_8)
                if (k.startsWith("https://") || k.startsWith("http://")) {
                    out[k] = v
                }
            }
        }
        return out
    }

    // ── Context-backed atomic persistence ───────────────────────────────────

    private fun storeDir(context: Context): File {
        val dir = File(context.filesDir, DIR_NAME)
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    private fun profilesFile(context: Context): File = File(storeDir(context), PROFILES_FILE)

    private fun jarFile(context: Context, profileId: String): File =
        File(storeDir(context), "jar_${sanitizeProfileId(profileId)}.txt")

    @Synchronized
    fun load(context: Context, defaultUrl: String = CommandCompat.AISTUDIO_URL): BrowserProfileState {
        val file = profilesFile(context)
        if (!file.isFile) {
            val initial = defaultState(defaultUrl)
            save(context, initial)
            return initial
        }
        return runCatching {
            val json = JSONObject(file.readText())
            val active = json.optString("activeProfileId", DEFAULT_PROFILE_ID)
            val arr = json.optJSONArray("profiles") ?: JSONArray()
            val list = ArrayList<BrowserProfile>(arr.length())
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                val id = o.optString("id").trim()
                if (id.isEmpty()) continue
                list.add(
                    BrowserProfile(
                        id = id,
                        name = o.optString("name", "Account ${i + 1}").ifBlank { "Account ${i + 1}" },
                        webkitName = o.optString("webkitName", webkitProfileNameFor(id)),
                        colorHex = o.optString("colorHex", PROFILE_COLORS[i % PROFILE_COLORS.size]),
                        detectedEmail = o.optString("detectedEmail", ""),
                        lastUrl = o.optString("lastUrl", defaultUrl).ifBlank { defaultUrl },
                        desktopMode = o.optBoolean("desktopMode", false),
                        createdAtMs = o.optLong("createdAtMs", 0L)
                    )
                )
            }
            if (list.isEmpty()) {
                defaultState(defaultUrl)
            } else {
                val safeActive = if (list.any { it.id == active }) active else list.first().id
                BrowserProfileState(safeActive, list)
            }
        }.getOrElse {
            defaultState(defaultUrl)
        }
    }

    @Synchronized
    fun save(context: Context, state: BrowserProfileState) {
        runCatching {
            val arr = JSONArray()
            for (p in state.profiles) {
                arr.put(
                    JSONObject().apply {
                        put("id", p.id)
                        put("name", p.name)
                        put("webkitName", p.webkitName)
                        put("colorHex", p.colorHex)
                        put("detectedEmail", p.detectedEmail)
                        put("lastUrl", p.lastUrl)
                        put("desktopMode", p.desktopMode)
                        put("createdAtMs", p.createdAtMs)
                    }
                )
            }
            val root = JSONObject().apply {
                put("activeProfileId", state.activeProfileId)
                put("profiles", arr)
            }
            val target = profilesFile(context)
            val tmp = File(target.parentFile, "${target.name}.tmp")
            tmp.writeText(root.toString(2))
            if (target.exists()) target.delete()
            tmp.renameTo(target)
        }
    }

    fun deleteProfileStorage(context: Context, profile: BrowserProfile) {
        runCatching { jarFile(context, profile.id).delete() }
        if (profile.webkitName != DEFAULT_WEBKIT_PROFILE &&
            WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)
        ) {
            runCatching { ProfileStore.getInstance().deleteProfile(profile.webkitName) }
        }
    }

    fun clearSessionData(context: Context, profile: BrowserProfile) {
        runCatching { jarFile(context, profile.id).delete() }
        if (WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)) {
            runCatching {
                val wp = ProfileStore.getInstance().getProfile(profile.webkitName)
                wp?.cookieManager?.removeAllCookies(null)
                wp?.cookieManager?.flush()
                wp?.webStorage?.deleteAllData()
            }
        } else {
            runCatching {
                val cm = CookieManager.getInstance()
                cm.removeAllCookies(null)
                cm.flush()
                WebStorage.getInstance().deleteAllData()
            }
        }
    }

    // ── Legacy single-profile WebView cookie-jar fallback ───────────────────

    fun snapshotLegacyCookies(context: Context, profileId: String, extraUrl: String? = null) {
        if (WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)) return
        runCatching {
            val cm = CookieManager.getInstance()
            val origins = LinkedHashSet(GOOGLE_SESSION_ORIGINS)
            extraUrl?.takeIf { it.startsWith("http") }?.let {
                val uri = URI(it)
                if (!uri.scheme.isNullOrBlank() && !uri.host.isNullOrBlank()) {
                    origins.add("${uri.scheme}://${uri.host}")
                }
            }
            val map = LinkedHashMap<String, String>()
            for (origin in origins) {
                val raw = cm.getCookie(origin)
                if (!raw.isNullOrBlank()) {
                    map[origin] = raw
                }
            }
            jarFile(context, profileId).writeText(encodeCookieJarEntries(map))
        }
    }

    fun restoreLegacyCookies(context: Context, profileId: String, onReady: () -> Unit) {
        if (WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)) {
            onReady()
            return
        }
        val cm = runCatching { CookieManager.getInstance() }.getOrNull()
        if (cm == null) {
            onReady()
            return
        }
        val file = jarFile(context, profileId)
        val restored = if (file.isFile) {
            decodeCookieJarEntries(runCatching { file.readText() }.getOrDefault(""))
        } else {
            emptyMap()
        }
        cm.removeAllCookies {
            runCatching { WebStorage.getInstance().deleteAllData() }
            for ((origin, header) in restored) {
                for (pair in header.split(';')) {
                    val kv = pair.trim()
                    if (kv.contains('=')) {
                        cm.setCookie(origin, "$kv; path=/; Secure")
                    }
                }
            }
            cm.flush()
            onReady()
        }
    }
}
