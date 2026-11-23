package com.dastyab.app

import android.content.Context
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * HarvestSourceStore — unified, persistent source manager and latency benchmarker
 * supporting all four censorship-resistant source classes:
 *  • `GITHUB_RAW`: GitHub raw config lists (with jsDelivr / Statically CDN mirror fallback)
 *  • `SUBSCRIPTION_URL`: arbitrary HTTP/HTTPS base64 / Clash / Sing-box / plain subscription URLs
 *  • `TELEGRAM_CHANNEL`: public `t.me/s/<channel>` feeds
 *  • `TELEGRAM_POST`: single `t.me/<channel>/<id>` drop posts
 *
 * Includes per-source telemetry (`lastFetchTimeMs`, `configsFound`, `successRate`),
 * JSON & text import/export, bulk multi-line paste, and pure-Kotlin serialization so
 * all normalization and round-trip tests run on plain JVM without `org.json`.
 */
object HarvestSourceStore {

    private const val PREFS_NAME = "dastyab_harvest_sources"
    private const val KEY_GITHUB_URLS = "github_urls"
    private const val KEY_TELEGRAM_CHANNELS = "telegram_channels"
    private const val KEY_DISABLED_DEFAULTS = "disabled_defaults"
    private const val KEY_UNIFIED_SOURCES_JSON = "unified_sources_json"

    enum class SourceType(val wireName: String, val displayLabel: String) {
        GITHUB_RAW("github_raw", "GitHub Raw"),
        SUBSCRIPTION_URL("subscription_url", "Subscription URL"),
        TELEGRAM_CHANNEL("telegram_channel", "Telegram Channel"),
        TELEGRAM_POST("telegram_post", "Telegram Post");

        companion object {
            fun fromWire(raw: String?): SourceType? {
                val clean = raw?.trim()?.lowercase() ?: return null
                return values().firstOrNull {
                    it.wireName == clean || it.name.equals(clean, ignoreCase = true)
                }
            }
        }
    }

    data class HarvestSource(
        val id: String,
        val name: String,
        val type: SourceType,
        val value: String,
        val enabled: Boolean = true,
        val isDefault: Boolean = false,
        val lastFetchTimeMs: Long = 0L,
        val configsFound: Int = 0,
        val attemptCount: Int = 0,
        val successCount: Int = 0
    ) {
        val successRate: Int
            get() = if (attemptCount <= 0) 0 else ((successCount * 100.0) / attemptCount).toInt().coerceIn(0, 100)
    }

    data class ConfigProbeResult(
        val uri: String,
        val protocol: String,
        val host: String,
        val port: Int,
        val latencyMs: Long,
        val reachable: Boolean,
        val tlsVerified: Boolean = false
    )

    val DEFAULT_SOURCES: List<HarvestSource> by lazy {
        val out = LinkedHashMap<String, HarvestSource>()
        fun putDefault(name: String, type: SourceType, value: String) {
            val id = makeSourceId(type, value)
            out.putIfAbsent(
                id,
                HarvestSource(
                    id = id,
                    name = name,
                    type = type,
                    value = value,
                    enabled = true,
                    isDefault = true
                )
            )
        }

        val githubCurated = listOf(
            "barry-far V2ray-Configs (VLESS)" to "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
            "barry-far V2ray-Configs (All)" to "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
            "Epodonios v2ray-configs (VLESS)" to "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
            "Epodonios v2ray-configs (All)" to "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
            "MahsaNetConfigTopic (Xray Final)" to "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/main/xray_final.txt",
            "yebekhe TVC (VLESS)" to "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless",
            "yebekhe TVC (Mix Base64)" to "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/base64/mix",
            "yebekhe TelegramV2rayCollector (Mix)" to "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
            "soroushmirzaei collector (Default)" to "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
            "soroushmirzaei collector (Hysteria)" to "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/hysteria",
            "soroushmirzaei collector (TUIC)" to "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/tuic",
            "NiREvil vless (Sub)" to "https://raw.githubusercontent.com/NiREvil/vless/main/sub/SSTime",
            "MrMohebi xray-proxy-grabber" to "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-v2ray-config/master/CollectedConfigs.txt",
            "SoliSpirit v2ray-configs" to "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
            "Danialsamadi v2go" to "https://raw.githubusercontent.com/Danialsamadi/v2go/main/All_Configs_Sub.txt",
            "peasoft NoMoreWalls" to "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
            "mfuu v2ray" to "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
            "mahdibland V2RayAggregator" to "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
            "AlienVPN402 Subscribe" to "https://raw.githubusercontent.com/AlienVPN402/AlienVPN402-subscribe-servers/main/index.html"
        )
        for ((name, url) in githubCurated) {
            putDefault(name, SourceType.GITHUB_RAW, url)
        }
        for (ch in ConfigHarvester.DEFAULT_TELEGRAM_CHANNELS) {
            putDefault("@$ch", SourceType.TELEGRAM_CHANNEL, ch)
        }
        out.values.toList()
    }

    fun makeSourceId(type: SourceType, value: String): String {
        return "${type.wireName}:${value.trim().lowercase()}"
    }

    /** Converts standard GitHub web URLs (`blob`) to raw URLs so users can paste any GitHub link. */
    fun normalizeGithubUrl(raw: String): String? {
        val trimmed = raw.trim()
        if (!trimmed.startsWith("http://", ignoreCase = true) &&
            !trimmed.startsWith("https://", ignoreCase = true)
        ) return null

        val githubBlobRegex = Regex(
            """^https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$""",
            RegexOption.IGNORE_CASE
        )
        val match = githubBlobRegex.matchEntire(trimmed)
        if (match != null) {
            val (owner, repo, branch, path) = match.destructured
            return "https://raw.githubusercontent.com/$owner/$repo/$branch/$path"
        }
        return trimmed
    }

    /** Validates and normalizes an arbitrary subscription HTTP/HTTPS URL. */
    fun normalizeSubscriptionUrl(raw: String): String? {
        val trimmed = raw.trim()
        if (!trimmed.startsWith("http://", ignoreCase = true) &&
            !trimmed.startsWith("https://", ignoreCase = true)
        ) return null
        if (trimmed.any { it.isWhitespace() }) return null
        return normalizeGithubUrl(trimmed)
    }

    /** Normalizes `@channel`, `t.me/channel`, `Telegram.me/channel`, `https://t.me/s/channel`, or bare username to `channel`. */
    fun normalizeTelegramChannel(raw: String): String? {
        var s = raw.trim()
        if (s.isEmpty()) return null
        s = s.replace(Regex("^(?i)(?:https?://)?(?:www\\.)?(?:t\\.me|telegram\\.me)/(?:s/)?"), "")
        s = s.removePrefix("@")
        s = s.substringBefore('/').substringBefore('?').trim()
        if (s.length < 3 || !s.all { it.isLetterOrDigit() || it == '_' }) return null
        return s
    }

    /** Normalizes a Telegram single-post link (`t.me/<channel>/<id>` or `t.me/s/<channel>/<id>`) to `https://t.me/<channel>/<id>`. */
    fun normalizeTelegramPost(raw: String): String? {
        val trimmed = raw.trim()
        val match = Regex(
            """^(?:https?://)?(?:www\.)?(?:t\.me|telegram\.me)/(?:s/)?([A-Za-z0-9_]{3,})/(\d+)(?:[/?#].*)?$""",
            RegexOption.IGNORE_CASE
        ).matchEntire(trimmed) ?: return null
        val (channel, postId) = match.destructured
        return "https://t.me/$channel/$postId"
    }

    /** Automatically classifies user input into one of the 4 supported [SourceType]s and normalizes its value. */
    fun classifySourceInput(raw: String, forcedType: SourceType? = null): Pair<SourceType, String>? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        if (forcedType != null) {
            val normalized = when (forcedType) {
                SourceType.GITHUB_RAW -> normalizeGithubUrl(trimmed)
                SourceType.SUBSCRIPTION_URL -> normalizeSubscriptionUrl(trimmed)
                SourceType.TELEGRAM_CHANNEL -> normalizeTelegramChannel(trimmed)
                SourceType.TELEGRAM_POST -> normalizeTelegramPost(trimmed)
            } ?: return null
            return forcedType to normalized
        }

        normalizeTelegramPost(trimmed)?.let { return SourceType.TELEGRAM_POST to it }
        if (trimmed.startsWith("http://", ignoreCase = true) ||
            trimmed.startsWith("https://", ignoreCase = true)
        ) {
            if (trimmed.contains("t.me/", ignoreCase = true) ||
                trimmed.contains("telegram.me/", ignoreCase = true)
            ) {
                normalizeTelegramChannel(trimmed)?.let { return SourceType.TELEGRAM_CHANNEL to it }
            }
            val url = normalizeGithubUrl(trimmed) ?: return null
            val isGithub = url.contains("raw.githubusercontent.com", ignoreCase = true) ||
                url.contains("cdn.jsdelivr.net/gh/", ignoreCase = true) ||
                url.contains("cdn.statically.io/gh/", ignoreCase = true) ||
                url.contains("github.com/", ignoreCase = true)
            return (if (isGithub) SourceType.GITHUB_RAW else SourceType.SUBSCRIPTION_URL) to url
        }
        normalizeTelegramChannel(trimmed)?.let { return SourceType.TELEGRAM_CHANNEL to it }
        return null
    }

    /** Parses bulk multi-line / comma-separated GitHub URLs and normalizes them. */
    fun parseBulkGithubUrls(bulkText: String): List<String> {
        return bulkText
            .split('\n', '\r', ',', ' ', '\t')
            .mapNotNull { normalizeGithubUrl(it) }
            .distinct()
    }

    /** Parses bulk multi-line / comma-separated Telegram channels and normalizes them. */
    fun parseBulkTelegramChannels(bulkText: String): List<String> {
        return bulkText
            .split('\n', '\r', ',', ' ', '\t')
            .mapNotNull { normalizeTelegramChannel(it) }
            .distinct()
    }

    /** Parses bulk multi-line / comma / space-separated sources across all 4 source types. */
    fun parseBulkSources(bulkText: String, forcedType: SourceType? = null): List<HarvestSource> {
        val out = LinkedHashMap<String, HarvestSource>()
        for (line in bulkText.lines()) {
            val cleanLine = line.trim()
            if (cleanLine.isEmpty() || cleanLine.startsWith("#")) continue
            val tokens = if (cleanLine.contains('|')) {
                listOf(cleanLine)
            } else {
                cleanLine.split(',', ' ', '\t')
            }
            for (rawToken in tokens) {
                val token = rawToken.trim()
                if (token.isEmpty()) continue
                var explicitType: SourceType? = forcedType
                var explicitName: String? = null
                var valueCandidate = token
                if (token.contains('|')) {
                    val parts = token.split('|').map { it.trim() }
                    when {
                        parts.size >= 3 -> {
                            explicitType = SourceType.fromWire(parts[0]) ?: forcedType
                            explicitName = parts[1].takeIf { it.isNotEmpty() }
                            valueCandidate = parts[2]
                        }
                        parts.size == 2 -> {
                            val parsedType = SourceType.fromWire(parts[0])
                            if (parsedType != null) {
                                explicitType = parsedType
                                valueCandidate = parts[1]
                            } else {
                                explicitName = parts[0].takeIf { it.isNotEmpty() }
                                valueCandidate = parts[1]
                            }
                        }
                    }
                }
                val classified = classifySourceInput(valueCandidate, explicitType) ?: continue
                val (type, normValue) = classified
                val id = makeSourceId(type, normValue)
                val name = explicitName ?: defaultNameFor(type, normValue)
                out.putIfAbsent(
                    id,
                    HarvestSource(
                        id = id,
                        name = name,
                        type = type,
                        value = normValue,
                        enabled = true,
                        isDefault = false
                    )
                )
            }
        }
        return out.values.toList()
    }

    private fun defaultNameFor(type: SourceType, value: String): String = when (type) {
        SourceType.TELEGRAM_CHANNEL -> "@$value"
        SourceType.TELEGRAM_POST -> value.substringAfter("t.me/", value)
        SourceType.GITHUB_RAW -> value.substringAfter("raw.githubusercontent.com/")
            .split('/')
            .take(2)
            .joinToString("/")
            .ifBlank { value.take(36) }
        SourceType.SUBSCRIPTION_URL -> value.substringAfter("://").substringBefore('/').ifBlank { "Subscription" }
    }

    /** Pure-Kotlin JSON serializer for portable backup/export of [HarvestSource] lists. */
    fun serializeSourcesJson(sources: List<HarvestSource>): String {
        val sb = StringBuilder()
        sb.append("[\n")
        sources.forEachIndexed { idx, s ->
            sb.append("  {")
            sb.append("\"id\":\"${jsonEscape(s.id)}\",")
            sb.append("\"name\":\"${jsonEscape(s.name)}\",")
            sb.append("\"type\":\"${jsonEscape(s.type.wireName)}\",")
            sb.append("\"value\":\"${jsonEscape(s.value)}\",")
            sb.append("\"enabled\":${s.enabled},")
            sb.append("\"isDefault\":${s.isDefault},")
            sb.append("\"lastFetchTimeMs\":${s.lastFetchTimeMs},")
            sb.append("\"configsFound\":${s.configsFound},")
            sb.append("\"attemptCount\":${s.attemptCount},")
            sb.append("\"successCount\":${s.successCount}")
            sb.append("}")
            if (idx + 1 < sources.size) sb.append(',')
            sb.append('\n')
        }
        sb.append(']')
        return sb.toString()
    }

    /** Pure-Kotlin JSON deserializer for [HarvestSource] lists (works on JVM unit tests without `org.json`). */
    @Suppress("UNCHECKED_CAST")
    fun parseSourcesJson(rawJson: String): List<HarvestSource> {
        val trimmed = rawJson.trim()
        if (!trimmed.startsWith("[")) return emptyList()
        val parsed = parseJsonArray(trimmed) ?: return emptyList()
        val out = LinkedHashMap<String, HarvestSource>()
        for (item in parsed) {
            val map = item as? Map<*, *> ?: continue
            val rawType = (map["type"] as? String)?.trim()
            val rawVal = (map["value"] as? String)?.trim().orEmpty()
            if (rawVal.isEmpty()) continue
            val classified = classifySourceInput(rawVal, SourceType.fromWire(rawType)) ?: continue
            val (type, normValue) = classified
            val id = makeSourceId(type, normValue)
            val name = (map["name"] as? String)?.trim()?.takeIf { it.isNotEmpty() }
                ?: defaultNameFor(type, normValue)
            val enabled = (map["enabled"] as? Boolean) ?: true
            val isDefault = (map["isDefault"] as? Boolean) ?: false
            val lastFetch = (map["lastFetchTimeMs"] as? Number)?.toLong() ?: 0L
            val found = (map["configsFound"] as? Number)?.toInt() ?: 0
            val attempts = (map["attemptCount"] as? Number)?.toInt() ?: 0
            val successes = (map["successCount"] as? Number)?.toInt() ?: 0
            out.putIfAbsent(
                id,
                HarvestSource(
                    id = id,
                    name = name,
                    type = type,
                    value = normValue,
                    enabled = enabled,
                    isDefault = isDefault,
                    lastFetchTimeMs = lastFetch.coerceAtLeast(0L),
                    configsFound = found.coerceAtLeast(0),
                    attemptCount = attempts.coerceAtLeast(0),
                    successCount = successes.coerceIn(0, attempts.coerceAtLeast(0))
                )
            )
        }
        return out.values.toList()
    }

    /** Exports [sources] as human-readable `type | name | value` lines. */
    fun exportSourcesText(sources: List<HarvestSource>): String {
        return sources.joinToString("\n") { s ->
            "${s.type.wireName} | ${s.name} | ${s.value}"
        }
    }

    fun getAllSources(context: Context): List<HarvestSource> {
        val p = prefs(context)
        val rawJson = p.getString(KEY_UNIFIED_SOURCES_JSON, null)
        if (!rawJson.isNullOrBlank()) {
            val parsed = parseSourcesJson(rawJson)
            if (parsed.isNotEmpty()) return parsed
        }
        // First-time seed: merge custom legacy lists (newest first) + expanded curated defaults
        val seeded = LinkedHashMap<String, HarvestSource>()
        for (url in getCustomGithubUrls(context)) {
            val norm = normalizeGithubUrl(url) ?: continue
            val type = classifySourceInput(norm)?.first ?: SourceType.GITHUB_RAW
            val id = makeSourceId(type, norm)
            seeded.putIfAbsent(
                id,
                HarvestSource(id, defaultNameFor(type, norm), type, norm, enabled = true, isDefault = false)
            )
        }
        for (ch in getCustomTelegramChannels(context)) {
            val norm = normalizeTelegramChannel(ch) ?: continue
            val id = makeSourceId(SourceType.TELEGRAM_CHANNEL, norm)
            seeded.putIfAbsent(
                id,
                HarvestSource(id, "@$norm", SourceType.TELEGRAM_CHANNEL, norm, enabled = true, isDefault = false)
            )
        }
        for (def in DEFAULT_SOURCES) {
            seeded.putIfAbsent(def.id, def)
        }
        val list = seeded.values.toList()
        saveSources(context, list)
        return list
    }

    fun saveSources(context: Context, sources: List<HarvestSource>) {
        val deduped = LinkedHashMap<String, HarvestSource>(sources.size)
        for (s in sources) {
            deduped[s.id] = s
        }
        val json = serializeSourcesJson(deduped.values.toList())
        prefs(context).edit().putString(KEY_UNIFIED_SOURCES_JSON, json).apply()
    }

    fun addSource(
        context: Context,
        name: String,
        type: SourceType,
        value: String
    ): HarvestSource? {
        val classified = classifySourceInput(value, type) ?: return null
        val (resolvedType, normValue) = classified
        val id = makeSourceId(resolvedType, normValue)
        val cleanName = name.trim().ifBlank { defaultNameFor(resolvedType, normValue) }
        val newItem = HarvestSource(
            id = id,
            name = cleanName,
            type = resolvedType,
            value = normValue,
            enabled = true,
            isDefault = false
        )
        val existing = getAllSources(context).filterNot { it.id == id }
        saveSources(context, listOf(newItem) + existing)
        return newItem
    }

    fun updateSource(
        context: Context,
        id: String,
        name: String,
        type: SourceType,
        value: String,
        enabled: Boolean
    ): Boolean {
        val classified = classifySourceInput(value, type) ?: return false
        val (resolvedType, normValue) = classified
        val newId = makeSourceId(resolvedType, normValue)
        val current = getAllSources(context)
        val old = current.firstOrNull { it.id == id } ?: return false
        val updated = old.copy(
            id = newId,
            name = name.trim().ifBlank { defaultNameFor(resolvedType, normValue) },
            type = resolvedType,
            value = normValue,
            enabled = enabled
        )
        val next = current.mapNotNull { item ->
            when (item.id) {
                id -> updated
                newId -> null
                else -> item
            }
        }
        saveSources(context, next)
        return true
    }

    fun removeSource(context: Context, id: String) {
        val next = getAllSources(context).filterNot { it.id == id }
        saveSources(context, next)
    }

    fun setSourceEnabled(context: Context, id: String, enabled: Boolean) {
        val next = getAllSources(context).map { s ->
            if (s.id == id) s.copy(enabled = enabled) else s
        }
        saveSources(context, next)
    }

    fun bulkAddSources(context: Context, bulkText: String, forcedType: SourceType? = null): Int {
        val incoming = parseBulkSources(bulkText, forcedType)
        if (incoming.isEmpty()) return 0
        val current = getAllSources(context)
        val existingIds = current.map { it.id }.toSet()
        val fresh = incoming.filterNot { it.id in existingIds }
        saveSources(context, fresh + current)
        return incoming.size
    }

    fun importSources(context: Context, rawText: String, replaceExisting: Boolean = false): Int {
        val trimmed = rawText.trim()
        if (trimmed.isEmpty()) return 0
        val imported = if (trimmed.startsWith("[")) {
            parseSourcesJson(trimmed)
        } else {
            parseBulkSources(trimmed)
        }
        if (imported.isEmpty()) return 0
        if (replaceExisting) {
            saveSources(context, imported)
        } else {
            val currentMap = getAllSources(context).associateByTo(LinkedHashMap()) { it.id }
            for (s in imported) {
                currentMap[s.id] = s
            }
            saveSources(context, currentMap.values.toList())
        }
        return imported.size
    }

    fun recordFetchResult(context: Context, sourceId: String, configsFound: Int, success: Boolean) {
        val now = System.currentTimeMillis()
        val current = getAllSources(context)
        var changed = false
        val next = current.map { s ->
            if (s.id == sourceId) {
                changed = true
                s.copy(
                    lastFetchTimeMs = now,
                    configsFound = configsFound.coerceAtLeast(0),
                    attemptCount = s.attemptCount + 1,
                    successCount = s.successCount + (if (success) 1 else 0)
                )
            } else {
                s
            }
        }
        if (changed) saveSources(context, next)
    }

    fun getCustomGithubUrls(context: Context): List<String> {
        val raw = prefs(context).getString(KEY_GITHUB_URLS, "") ?: ""
        return raw.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.distinct().toList()
    }

    fun saveCustomGithubUrls(context: Context, urls: List<String>) {
        val clean = urls.mapNotNull { normalizeGithubUrl(it) }.distinct()
        prefs(context).edit().putString(KEY_GITHUB_URLS, clean.joinToString("\n")).apply()
    }

    fun addGithubUrls(context: Context, bulkText: String): Int {
        val incoming = parseBulkGithubUrls(bulkText)
        if (incoming.isEmpty()) return 0
        val merged = (incoming + getCustomGithubUrls(context)).distinct()
        saveCustomGithubUrls(context, merged)
        bulkAddSources(context, incoming.joinToString("\n"), SourceType.GITHUB_RAW)
        return incoming.size
    }

    fun removeGithubUrl(context: Context, url: String) {
        val updated = getCustomGithubUrls(context).filterNot { it == url }
        saveCustomGithubUrls(context, updated)
        removeSource(context, makeSourceId(SourceType.GITHUB_RAW, url))
    }

    fun getCustomTelegramChannels(context: Context): List<String> {
        val raw = prefs(context).getString(KEY_TELEGRAM_CHANNELS, "") ?: ""
        return raw.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.distinct().toList()
    }

    fun saveCustomTelegramChannels(context: Context, channels: List<String>) {
        val clean = channels.mapNotNull { normalizeTelegramChannel(it) }.distinct()
        prefs(context).edit().putString(KEY_TELEGRAM_CHANNELS, clean.joinToString("\n")).apply()
    }

    fun addTelegramChannels(context: Context, bulkText: String): Int {
        val incoming = parseBulkTelegramChannels(bulkText)
        if (incoming.isEmpty()) return 0
        val merged = (incoming + getCustomTelegramChannels(context)).distinct()
        saveCustomTelegramChannels(context, merged)
        bulkAddSources(context, incoming.joinToString("\n"), SourceType.TELEGRAM_CHANNEL)
        return incoming.size
    }

    fun removeTelegramChannel(context: Context, channel: String) {
        val updated = getCustomTelegramChannels(context).filterNot { it.equals(channel, ignoreCase = true) }
        saveCustomTelegramChannels(context, updated)
        val norm = normalizeTelegramChannel(channel) ?: channel
        removeSource(context, makeSourceId(SourceType.TELEGRAM_CHANNEL, norm))
    }

    fun resetToDefaults(context: Context) {
        prefs(context).edit()
            .remove(KEY_GITHUB_URLS)
            .remove(KEY_TELEGRAM_CHANNELS)
            .remove(KEY_DISABLED_DEFAULTS)
            .putString(KEY_UNIFIED_SOURCES_JSON, serializeSourcesJson(DEFAULT_SOURCES))
            .apply()
    }

    /** Extracts `(host, port)` from any supported proxy/VPN URI or WireGuard INI config for latency probing. */
    fun extractHostAndPort(uri: String): Pair<String, Int>? {
        return UniversalConfig.extractHostAndPort(uri)
    }

    /**
     * Benchmarks up to [maxToTest] harvested configs in parallel (performing TLS + SNI handshake
     * checks on TLS-enabled TCP transports when [verifyTls] is true, and TCP connect elsewhere)
     * and returns only reachable endpoints sorted fastest-first.
     */
    fun benchmarkHarvestedConfigs(
        configs: List<String>,
        maxToTest: Int = 25,
        timeoutMs: Int = 1800,
        verifyTls: Boolean = true
    ): List<ConfigProbeResult> {
        val candidates = configs.take(maxToTest).mapNotNull { uri ->
            extractHostAndPort(uri)?.let { (host, port) -> Triple(uri, host, port) }
        }
        if (candidates.isEmpty()) return emptyList()
        val pool = Executors.newFixedThreadPool(8)
        return try {
            val tasks = candidates.map { (uri, host, port) ->
                Callable {
                    val proto = UniversalConfig.canonicalProtocol(ConfigHarvester.protocolOf(uri))
                    val tlsSni = if (verifyTls) extractTlsSniCandidate(uri, proto, host) else null
                    val ms: Long
                    val tlsOk: Boolean
                    if (tlsSni != null) {
                        val tlsLatency = CleanEndpointScout.probeTlsWithSni(host, port, tlsSni, timeoutMs)
                        if (tlsLatency >= 0) {
                            ms = tlsLatency
                            tlsOk = true
                        } else {
                            ms = CleanEndpointScout.probeTcpLatency(host, port, timeoutMs)
                            tlsOk = false
                        }
                    } else {
                        ms = CleanEndpointScout.probeTcpLatency(host, port, timeoutMs)
                        tlsOk = false
                    }
                    ConfigProbeResult(
                        uri = uri,
                        protocol = proto,
                        host = host,
                        port = port,
                        latencyMs = ms,
                        reachable = ms >= 0,
                        tlsVerified = tlsOk
                    )
                }
            }
            pool.invokeAll(tasks, 18, TimeUnit.SECONDS)
                .mapNotNull { runCatching { it.get() }.getOrNull() }
                .filter { it.reachable }
                .sortedBy { it.latencyMs }
        } finally {
            pool.shutdownNow()
        }
    }

    private fun extractTlsSniCandidate(uri: String, canonicalProto: String, host: String): String? {
        if (canonicalProto !in setOf("vless", "trojan", "anytls", "naive+https", "https")) {
            return null
        }
        val query = uri.substringAfter('?', "").substringBefore('#')
        val params = LinkedHashMap<String, String>()
        if (query.isNotBlank()) {
            for (pair in query.split('&')) {
                val eq = pair.indexOf('=')
                if (eq > 0) {
                    params[pair.substring(0, eq).lowercase()] = pair.substring(eq + 1)
                }
            }
        }
        if (canonicalProto == "vless") {
            val sec = params["security"]?.lowercase().orEmpty()
            if (sec.isNotEmpty() && sec !in setOf("tls", "reality")) return null
        }
        return params["sni"]?.takeIf { it.isNotBlank() }
            ?: params["peer"]?.takeIf { it.isNotBlank() }
            ?: params["host"]?.takeIf { it.isNotBlank() }
            ?: host
    }

    private fun parseJsonArray(input: String): List<Any?>? {
        var pos = 0
        val len = input.length

        fun skipWs() {
            while (pos < len && input[pos].isWhitespace()) pos++
        }

        fun parseString(): String? {
            if (pos >= len || input[pos] != '"') return null
            pos++
            val sb = StringBuilder()
            while (pos < len) {
                val c = input[pos++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        if (pos >= len) return null
                        when (val esc = input[pos++]) {
                            '"', '\\', '/' -> sb.append(esc)
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 <= len) {
                                    val code = input.substring(pos, pos + 4).toIntOrNull(16)
                                    if (code != null) sb.append(code.toChar())
                                    pos += 4
                                }
                            }
                            else -> sb.append(esc)
                        }
                    }
                    else -> sb.append(c)
                }
            }
            return null
        }

        fun parseValue(): Any? {
            skipWs()
            if (pos >= len) return null
            return when (input[pos]) {
                '{' -> {
                    pos++
                    val map = LinkedHashMap<String, Any?>()
                    skipWs()
                    if (pos < len && input[pos] == '}') {
                        pos++
                        return map
                    }
                    while (pos < len) {
                        skipWs()
                        val k = parseString() ?: return null
                        skipWs()
                        if (pos >= len || input[pos] != ':') return null
                        pos++
                        map[k] = parseValue()
                        skipWs()
                        if (pos < len && input[pos] == ',') {
                            pos++
                            continue
                        }
                        if (pos < len && input[pos] == '}') {
                            pos++
                            return map
                        }
                        return null
                    }
                    null
                }
                '[' -> {
                    pos++
                    val list = ArrayList<Any?>()
                    skipWs()
                    if (pos < len && input[pos] == ']') {
                        pos++
                        return list
                    }
                    while (pos < len) {
                        list.add(parseValue())
                        skipWs()
                        if (pos < len && input[pos] == ',') {
                            pos++
                            continue
                        }
                        if (pos < len && input[pos] == ']') {
                            pos++
                            return list
                        }
                        return null
                    }
                    null
                }
                '"' -> parseString()
                't' -> if (input.startsWith("true", pos)) { pos += 4; true } else null
                'f' -> if (input.startsWith("false", pos)) { pos += 5; false } else null
                'n' -> if (input.startsWith("null", pos)) { pos += 4; null } else null
                else -> {
                    val start = pos
                    while (pos < len && (input[pos].isDigit() || input[pos] in "-+.eE")) pos++
                    if (pos == start) return null
                    val numStr = input.substring(start, pos)
                    numStr.toLongOrNull() ?: numStr.toDoubleOrNull() ?: numStr
                }
            }
        }

        @Suppress("UNCHECKED_CAST")
        return parseValue() as? List<Any?>
    }

    private fun jsonEscape(value: String): String {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")
    }

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
}
