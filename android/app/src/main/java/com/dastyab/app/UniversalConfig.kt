package com.dastyab.app

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder

/**
 * UniversalConfig — pure-Kotlin multi-protocol config extractor, parser, and WireGuard INI codec.
 *
 * Supports:
 *  • Xray / Sing-box URIs: `vless://`, `vmess://`, `trojan://`, `ss://`, `ssr://`,
 *    `hy2://`, `hysteria2://`, `hysteria://`, `tuic://`, `juicity://`, `anytls://`,
 *    `naive+https://`, `naive+quic://`, `naive://`
 *  • WireGuard / WARP / AmneziaWG: `wireguard://`, `wg://`, `warp://`, `amneziawg://`,
 *    PLUS raw INI `[Interface] ... [Peer]` `.conf` text blocks (with lossless round-trip conversion)
 *  • NapsternetV: `npv://`, `npv4://`, `napsternetv://` (both URI and Base64 JSON forms)
 *  • Proxy / Tunnel / Stealth: `socks5://`, `socks4://`, `socks://`, `ssh://`, `sn://`, `dnstt://`, `slipnet://`
 *  • Telegram MTProto proxies: `tg://proxy?server=...&port=...&secret=...` and `https://t.me/proxy?...`
 *
 * Pure Kotlin (no `org.json` Android stubs) so all extraction, WireGuard INI conversion,
 * Base64 decoding, and host/port parsing run identically on Android and plain JVM unit tests.
 */
object UniversalConfig {

    enum class Family(val displayName: String) {
        XRAY_SINGBOX("Xray / Sing-box"),
        WIREGUARD("WireGuard / WARP"),
        OPENVPN("OpenVPN"),
        NAPSTERNETV("NapsternetV"),
        PROXY_TUNNEL("SOCKS / SSH / Stealth"),
        TELEGRAM_MTPROTO("Telegram MTProto")
    }

    data class ParsedEndpoint(
        val uri: String,
        val protocol: String,
        val family: Family,
        val host: String,
        val port: Int,
        val label: String,
        val id: String = ""
    ) {
        fun summary(): String {
            val tag = if (label.isNotBlank()) "$label · " else ""
            return "$tag$host:$port (${protocol.uppercase()})"
        }
    }

    private val SUPPORTED_PROTOCOLS = setOf(
        "vless", "vmess", "trojan", "ss", "ssr",
        "hysteria2", "hysteria", "hy2", "tuic",
        "juicity", "anytls", "naive+https", "naive+quic", "naive",
        "wireguard", "wg", "warp", "amneziawg",
        "openvpn", "ovpn",
        "npv4", "npvs", "npvt", "npv", "napsternetv",
        "socks5", "socks4", "socks", "http", "https", "ssh",
        "sn", "dnstt", "slipnet",
        "mtproto"
    )

    private val SUPPORTED_SCHEME_PATTERN = listOf(
        "vless", "vmess", "trojan", "ss", "ssr",
        "hysteria2", "hysteria", "hy2", "tuic",
        "juicity", "anytls", "naive\\+https", "naive\\+quic", "naive",
        "wireguard", "wg", "warp", "amneziawg",
        "openvpn", "ovpn",
        "npv4", "npvs", "npvt", "npv", "napsternetv",
        "socks5", "socks4", "socks", "ssh",
        "sn", "dnstt", "slipnet"
    ).joinToString("|")

    private val URI_REGEX = Regex(
        """(?<![A-Za-z0-9+.-])(?:$SUPPORTED_SCHEME_PATTERN)://[^\s"'<>`\\]+""",
        RegexOption.IGNORE_CASE
    )

    private val HTTP_PROXY_URI_REGEX = Regex(
        """(?<![A-Za-z0-9+.-])https?://(?:[^\s"'<>`\\@]+@)?(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):(\d{1,5})(?:/)?(?:#[^\s"'<>`\\]*)?(?=[\s"'<>`,;|#\r\n]|$)""",
        RegexOption.IGNORE_CASE
    )

    private val MTPROTO_URI_REGEX = Regex(
        """(?<![A-Za-z0-9+./-])(?:tg://proxy\?[^\s"'<>`\\]+|https?://(?:t\.me|telegram\.me)/proxy\?[^\s"'<>`\\]+)""",
        RegexOption.IGNORE_CASE
    )

    private val TG_SOCKS_URI_REGEX = Regex(
        """(?<![A-Za-z0-9+./-])(?:tg://socks\?[^\s"'<>`\\]+|https?://(?:t\.me|telegram\.me)/socks\?[^\s"'<>`\\]+)""",
        RegexOption.IGNORE_CASE
    )

    private val WEB_NON_PROXY_HOSTS = setOf(
        "t.me", "telegram.me", "telegram.dog",
        "github.com", "raw.githubusercontent.com", "gist.github.com",
        "cdn.jsdelivr.net", "cdn.statically.io",
        "youtube.com", "www.youtube.com", "youtu.be",
        "twitter.com", "x.com", "instagram.com", "google.com", "www.google.com"
    )

    private val B64_TOKEN_REGEX = Regex("""[A-Za-z0-9+/_=-]{32,}""")

    /** Returns true when an HTTP(S) URL is a web/channel/repo link (t.me, github.com, etc.), NOT an explicit proxy endpoint. */
    fun isNonProxyHttpUrl(raw: String): Boolean {
        val trimmed = raw.trim()
        val offset = when {
            trimmed.startsWith("https://", ignoreCase = true) -> 8
            trimmed.startsWith("http://", ignoreCase = true) -> 7
            else -> return false
        }
        val rest = trimmed.substring(offset)
        val noFrag = rest.substringBefore('#')
        val authAndPath = noFrag.substringBefore('?')
        if (noFrag.contains('?')) return true
        val slashIdx = authAndPath.indexOf('/')
        if (slashIdx >= 0 && authAndPath.substring(slashIdx).length > 1) return true
        val authority = if (slashIdx >= 0) authAndPath.substring(0, slashIdx) else authAndPath
        val hostPort = if (authority.contains('@')) authority.substringAfterLast('@') else authority
        val hp = splitHostPort(hostPort) ?: return true
        val hostLower = hp.first.lowercase()
        if (hostLower in WEB_NON_PROXY_HOSTS || hostLower.endsWith(".t.me") || hostLower.endsWith(".github.com")) {
            return true
        }
        return false
    }

    /** Extracts every supported config URI (including WireGuard INI, OpenVPN, Clash YAML, JSON outbounds, MTProto, and nested Base64). */
    fun extractAll(rawPayload: String, maxConfigs: Int = 4096): List<String> {
        if (rawPayload.isBlank()) return emptyList()
        val unescaped = unescapeHtml(rawPayload)
        val found = LinkedHashSet<String>()

        collectDirectMatches(unescaped, found)

        // Multi-round decode when entire payload looks like a Base64 subscription (up to 3 layers)
        var current = unescaped
        for (round in 0 until 3) {
            val fullDecoded = tryDecodeBase64(current) ?: break
            collectDirectMatches(fullDecoded, found)
            current = fullDecoded
        }

        // Also scan standalone Base64 blobs embedded inside Telegram messages or mixed subscriptions
        var decodedChunks = 0
        for (match in B64_TOKEN_REGEX.findAll(unescaped)) {
            if (decodedChunks >= 256) break
            val token = match.value
            val start = match.range.first
            val prefixWindow = unescaped.substring((start - 14).coerceAtLeast(0), start)
            if (prefixWindow.contains("://")) continue

            var inner = tryDecodeBase64(token) ?: continue
            for (r in 0 until 2) {
                val hasMarker = inner.contains("://") ||
                    inner.contains("[Interface]", ignoreCase = true) ||
                    inner.contains("\"outbounds\"") ||
                    inner.contains("proxies:")
                if (hasMarker) {
                    decodedChunks++
                    collectDirectMatches(inner, found)
                }
                inner = tryDecodeBase64(inner) ?: break
            }
        }

        return found
            .sortedWith(compareBy<String> { priorityRank(it) }.thenBy { it.length })
            .take(maxConfigs)
    }

    private fun collectDirectMatches(text: String, out: LinkedHashSet<String>) {
        URI_REGEX.findAll(text).forEach { m ->
            val cleaned = cleanUri(m.value)
            if (isPlausible(cleaned)) out.add(cleaned)
        }
        HTTP_PROXY_URI_REGEX.findAll(text).forEach { m ->
            val cleaned = cleanUri(m.value)
            if (!isNonProxyHttpUrl(cleaned) && parse(cleaned) != null) out.add(cleaned)
        }
        MTPROTO_URI_REGEX.findAll(text).forEach { m ->
            val cleaned = cleanUri(m.value)
            if (parse(cleaned) != null) out.add(cleaned)
        }
        TG_SOCKS_URI_REGEX.findAll(text).forEach { m ->
            val cleaned = cleanUri(m.value)
            if (parse(cleaned) != null) out.add(cleaned)
        }
        extractWireGuardIniBlocks(text).forEach { wgUri ->
            if (parse(wgUri) != null) out.add(wgUri)
        }
        extractOpenVpnConfigs(text).forEach { ovpnUri ->
            if (parse(ovpnUri) != null) out.add(ovpnUri)
        }
        extractClashYamlConfigs(text).forEach { clashUri ->
            if (parse(clashUri) != null) out.add(clashUri)
        }
        extractJsonConfigs(text).forEach { jsonUri ->
            if (parse(jsonUri) != null) out.add(jsonUri)
        }
    }

    /**
     * Extracts inline OpenVPN (`.ovpn` / `.openvpn`) profile directives posted in text/files
     * (`remote <host> <port>` paired with `client` / `dev ` / `proto ` / `<ca>`) into
     * normalized `openvpn://host:port?proto=...&dev=...#OpenVPN` URIs.
     */
    fun extractOpenVpnConfigs(rawText: String, label: String = "OpenVPN"): List<String> {
        if (!rawText.contains("remote ", ignoreCase = true)) return emptyList()
        val normalized = rawText.replace("\r\n", "\n").replace('\r', '\n')
        val lines = normalized.lines()
        val hasOvpnDirective = lines.any { line ->
            val t = line.trim().lowercase()
            t == "client" ||
                t.startsWith("dev ") ||
                t.startsWith("proto ") ||
                t.startsWith("<ca>") ||
                t.startsWith("<tls-auth>") ||
                t.startsWith("<tls-crypt>")
        }
        if (!hasOvpnDirective) return emptyList()

        var proto = "udp"
        var dev = "tun"
        var cipher = ""
        val out = LinkedHashSet<String>()
        for (rawLine in lines) {
            val clean = rawLine.substringBefore('#').substringBefore(';').trim()
            if (clean.isEmpty()) continue
            val parts = clean.split(Regex("\\s+"))
            if (parts.isEmpty()) continue
            when (parts[0].lowercase()) {
                "proto" -> if (parts.size >= 2) proto = parts[1].lowercase()
                "dev" -> if (parts.size >= 2) dev = parts[1].lowercase()
                "cipher", "data-ciphers" -> if (parts.size >= 2) cipher = parts[1]
                "http-proxy", "socks-proxy" -> if (parts.size >= 3) {
                    val host = parts[1].trim()
                    val port = parts[2].toIntOrNull()?.takeIf { it in 1..65535 }
                    if (port != null && host.isNotEmpty() && !host.contains('/') && !host.any { it.isWhitespace() }) {
                        val scheme = if (parts[0].equals("socks-proxy", true)) "socks5" else "http"
                        val formattedHost = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
                        out.add("$scheme://$formattedHost:$port")
                    }
                }
                "remote" -> if (parts.size >= 2) {
                    val host = parts[1].trim()
                    val port = parts.getOrNull(2)?.toIntOrNull()?.takeIf { it in 1..65535 } ?: 1194
                    val lineProto = parts.getOrNull(3)?.lowercase() ?: proto
                    if (host.isNotEmpty() && !host.contains('/') && !host.any { it.isWhitespace() }) {
                        proto = lineProto
                        val formattedHost = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
                        val qp = mutableListOf("proto=${urlEncode(proto)}", "dev=${urlEncode(dev)}")
                        if (cipher.isNotBlank()) qp.add("cipher=${urlEncode(cipher)}")
                        val frag = urlEncode(label.ifBlank { "OpenVPN-$host" })
                        out.add("openvpn://$formattedHost:$port?${qp.joinToString("&")}#$frag")
                    }
                }
            }
        }
        return out.toList()
    }

    /** Extracts Clash / Mihomo YAML proxy blocks (both flow `- {...}` and multi-line `- name:` items) into share URIs. */
    fun extractClashYamlConfigs(rawText: String): List<String> {
        if (!rawText.contains("server:", ignoreCase = true) ||
            (!rawText.contains("proxies:", ignoreCase = true) && !rawText.contains("type:", ignoreCase = true))
        ) {
            return emptyList()
        }
        val out = LinkedHashSet<String>()
        val normalized = rawText.replace("\r\n", "\n").replace('\r', '\n')

        fun buildFromMap(fields: Map<String, String>) {
            val type = fields["type"]?.lowercase()?.trim() ?: return
            val host = fields["server"]?.trim()?.trim('"', '\'') ?: return
            val port = fields["port"]?.trim()?.trim('"', '\'')?.toIntOrNull() ?: return
            if (host.isBlank() || host == "127.0.0.1" || host == "0.0.0.0" || port !in 1..65535) return
            val h = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
            val name = urlEncode((fields["name"] ?: "Clash-$type").trim('"', '\''))
            val sni = fields["sni"] ?: fields["servername"] ?: fields["server-name"] ?: ""
            val pass = fields["password"] ?: fields["auth-str"] ?: fields["auth"] ?: fields["uuid"] ?: "dastyab"
            val uuid = fields["uuid"] ?: fields["id"] ?: "11111111-1111-1111-1111-111111111111"
            val user = fields["username"] ?: ""
            val network = fields["network"] ?: "tcp"
            val tlsEnabled = fields["tls"]?.equals("true", ignoreCase = true) == true
            val userAuth = if (user.isNotBlank() && fields["password"]?.isNotBlank() == true) {
                "${urlEncode(user)}:${urlEncode(fields["password"]!!)}@"
            } else if (user.isNotBlank()) {
                "${urlEncode(user)}@"
            } else {
                ""
            }
            val uri = when (type) {
                "vless" -> "vless://${urlEncode(uuid)}@$h:$port?type=${urlEncode(network)}" +
                    (if (sni.isNotBlank()) "&sni=${urlEncode(sni)}" else "") + "#$name"
                "vmess" -> {
                    val aid = fields["alterid"] ?: fields["aid"] ?: "0"
                    val net = urlEncode(network).replace("%20", "")
                    val vmessJson = """{"v":"2","ps":"${jsonEscape(fields["name"] ?: "Clash-vmess")}","add":"${jsonEscape(host)}","port":"$port","id":"${jsonEscape(uuid)}","aid":"$aid","net":"$net","type":"none","tls":"${if (tlsEnabled) "tls" else ""}","sni":"${jsonEscape(sni)}"}"""
                    "vmess://${encodeBase64UrlSafe(vmessJson)}"
                }
                "trojan" -> "trojan://${urlEncode(pass)}@$h:$port" +
                    (if (sni.isNotBlank()) "?sni=${urlEncode(sni)}" else "") + "#$name"
                "hy2", "hysteria2" -> "hy2://${urlEncode(pass)}@$h:$port" +
                    (if (sni.isNotBlank()) "?sni=${urlEncode(sni)}" else "") + "#$name"
                "hysteria" -> {
                    val auth = fields["auth-str"] ?: fields["auth"] ?: fields["password"] ?: ""
                    val qp = buildList {
                        if (sni.isNotBlank()) add("sni=${urlEncode(sni)}")
                        if (auth.isNotBlank()) add("auth=${urlEncode(auth)}")
                    }.joinToString("&")
                    val q = if (qp.isNotEmpty()) "?$qp" else ""
                    "hysteria://$h:$port$q#$name"
                }
                "tuic" -> "tuic://${urlEncode(uuid)}:${urlEncode(pass)}@$h:$port" +
                    (if (sni.isNotBlank()) "?sni=${urlEncode(sni)}" else "") + "#$name"
                "juicity" -> "juicity://${urlEncode(uuid)}:${urlEncode(pass)}@$h:$port" +
                    (if (sni.isNotBlank()) "?sni=${urlEncode(sni)}" else "") + "#$name"
                "anytls" -> "anytls://${urlEncode(pass)}@$h:$port" +
                    (if (sni.isNotBlank()) "?sni=${urlEncode(sni)}" else "") + "#$name"
                "naive", "naive+https", "naive+quic" -> {
                    val scheme = if (type == "naive+quic") "naive+quic" else "naive+https"
                    "$scheme://$userAuth$h:$port" +
                        (if (sni.isNotBlank()) "?sni=${urlEncode(sni)}" else "") + "#$name"
                }
                "wireguard", "wg" -> "wireguard://${urlEncode(fields["private-key"] ?: pass)}@$h:$port" +
                    (if (!fields["public-key"].isNullOrBlank()) "?publickey=${urlEncode(fields["public-key"]!!)}" else "") + "#$name"
                "socks5", "socks" -> "socks5://$userAuth$h:$port#$name"
                "http" -> "${if (tlsEnabled) "https" else "http"}://$userAuth$h:$port#$name"
                "https" -> "https://$userAuth$h:$port#$name"
                "ss" -> {
                    val cipher = fields["cipher"] ?: "aes-256-gcm"
                    "ss://${urlEncode(cipher)}:${urlEncode(pass)}@$h:$port#$name"
                }
                "ssr" -> {
                    val cipher = fields["cipher"] ?: "aes-256-cfb"
                    val ssrProto = fields["protocol"] ?: "origin"
                    val obfs = fields["obfs"] ?: "plain"
                    val passB64 = encodeBase64UrlSafe(pass)
                    val ssrRaw = "$host:$port:$ssrProto:$cipher:$obfs:$passB64"
                    "ssr://${encodeBase64UrlSafe(ssrRaw)}#$name"
                }
                else -> null
            }
            if (uri != null && parse(uri) != null) out.add(uri)
        }

        // 1. Flow items: - {name: "...", type: vless, server: 1.2.3.4, port: 443}
        val flowRegex = Regex("""-\s*\{([^\}\n]{12,1024})\}""")
        for (m in flowRegex.findAll(normalized)) {
            val map = LinkedHashMap<String, String>()
            for (part in m.groupValues[1].split(',')) {
                val colon = part.indexOf(':')
                if (colon > 0) {
                    val k = part.substring(0, colon).trim().lowercase()
                    val v = part.substring(colon + 1).trim().trim('"', '\'')
                    if (v.isNotEmpty()) map[k] = v
                }
            }
            buildFromMap(map)
        }

        // 2. Block items: - name: ... \n  type: ... \n  server: ... \n  port: ...
        var currentMap = LinkedHashMap<String, String>()
        var inProxyItem = false
        for (rawLine in normalized.lines()) {
            val trimmed = rawLine.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
            if (trimmed.startsWith("- ") && !trimmed.startsWith("- {")) {
                if (inProxyItem) buildFromMap(currentMap)
                currentMap = LinkedHashMap()
                inProxyItem = true
                val rest = trimmed.substring(2).trim()
                val colon = rest.indexOf(':')
                if (colon > 0) {
                    currentMap[rest.substring(0, colon).trim().lowercase()] =
                        rest.substring(colon + 1).trim().trim('"', '\'')
                }
            } else if (inProxyItem) {
                val isIndented = rawLine.startsWith(" ") || rawLine.startsWith("\t")
                if (!isIndented) {
                    buildFromMap(currentMap)
                    currentMap = LinkedHashMap()
                    inProxyItem = false
                } else {
                    val colon = trimmed.indexOf(':')
                    if (colon > 0) {
                        val k = trimmed.substring(0, colon).trim().lowercase()
                        val v = trimmed.substring(colon + 1).trim().trim('"', '\'')
                        if (v.isNotEmpty()) currentMap[k] = v
                    }
                }
            }
        }
        if (inProxyItem) buildFromMap(currentMap)
        return out.toList()
    }

    /** Extracts Sing-Box / Xray JSON outbounds and legacy VMess JSON blobs into share URIs (pure Kotlin). */
    fun extractJsonConfigs(rawText: String): List<String> {
        if (!rawText.contains('{') || (!rawText.contains("\"server\"") && !rawText.contains("\"address\"") && !rawText.contains("\"add\""))) {
            return emptyList()
        }
        val out = LinkedHashSet<String>()
        val objects = scanBalancedJsonObjects(rawText, maxObjects = 256)
        for (objText in objects) {
            val parsedVal = parseJsonValue(objText) as? Map<*, *>
            if (parsedVal != null) {
                extractFromParsedJsonObject(parsedVal, objText, out)
            } else {
                extractFallbackJsonObject(objText, out)
            }
        }
        return out.toList()
    }

    @Suppress("UNCHECKED_CAST")
    private fun extractFromParsedJsonObject(
        obj: Map<*, *>,
        rawObjText: String,
        out: LinkedHashSet<String>
    ) {
        val outbounds = obj["outbounds"] as? List<*>
        if (outbounds != null) {
            for (item in outbounds) {
                if (item is Map<*, *>) {
                    extractFromParsedJsonObject(item, "", out)
                }
            }
        }

        // Legacy VMess JSON: {"add":"...", "port": 443, "id":"..."}
        val legacyAdd = jsonStr(obj["add"])
        if (legacyAdd != null && (jsonStr(obj["id"]) != null || jsonStr(obj["v"]) != null)) {
            val port = jsonPort(obj["port"])
            if (port != null && legacyAdd != "127.0.0.1" && legacyAdd != "0.0.0.0") {
                val serialized = rawObjText.takeIf { it.isNotBlank() && !it.contains("\"outbounds\"") }
                    ?: buildString {
                        append('{')
                        append("\"v\":\"2\",")
                        append("\"ps\":\"${jsonEscape(jsonStr(obj["ps"]) ?: "VMess")}\",")
                        append("\"add\":\"${jsonEscape(legacyAdd)}\",")
                        append("\"port\":\"$port\",")
                        append("\"id\":\"${jsonEscape(jsonStr(obj["id"]).orEmpty())}\"")
                        append('}')
                    }
                val vmessUri = "vmess://${encodeBase64UrlSafe(serialized)}"
                if (parse(vmessUri) != null) out.add(vmessUri)
                return
            }
        }

        val protoType = (jsonStr(obj["type"]) ?: jsonStr(obj["protocol"]))?.lowercase()
        if (protoType in setOf("direct", "block", "dns", "selector", "urltest", "freedom", "blackhole")) {
            return
        }

        val tlsMap = obj["tls"] as? Map<*, *>
        val streamMap = obj["streamSettings"] as? Map<*, *>
        val tlsSettingsMap = streamMap?.get("tlsSettings") as? Map<*, *>
        val transportMap = obj["transport"] as? Map<*, *>
        val sni = jsonStr(obj["sni"])
            ?: jsonStr(tlsMap?.get("server_name"))
            ?: jsonStr(tlsSettingsMap?.get("serverName"))
            ?: ""
        val tlsEnabled = (tlsMap?.get("enabled") as? Boolean) == true ||
            jsonStr(streamMap?.get("security"))?.equals("tls", ignoreCase = true) == true
        val net = jsonStr(transportMap?.get("type"))
            ?: jsonStr(streamMap?.get("network"))
            ?: jsonStr(obj["network"])
            ?: ""
        val tagStr = jsonStr(obj["tag"]) ?: jsonStr(obj["ps"]) ?: jsonStr(obj["name"]) ?: "JSON-${protoType ?: "proxy"}"

        // Nested Xray settings: vnext / servers / peers
        val settingsMap = obj["settings"] as? Map<*, *>
        val vnextList = settingsMap?.get("vnext") as? List<*>
        if (vnextList != null) {
            for (vItem in vnextList) {
                val vMap = vItem as? Map<*, *> ?: continue
                val addr = jsonStr(vMap["address"]) ?: continue
                val port = jsonPort(vMap["port"]) ?: continue
                if (addr == "127.0.0.1" || addr == "0.0.0.0") continue
                val users = vMap["users"] as? List<*>
                val firstUser = users?.firstOrNull() as? Map<*, *>
                val uid = jsonStr(firstUser?.get("id")) ?: jsonStr(firstUser?.get("uuid")) ?: "11111111-1111-1111-1111-111111111111"
                val scheme = if (protoType == "vmess") "vmess" else "vless"
                buildJsonShareUri(scheme, addr, port, uid, "", "", sni, net, tagStr, tlsEnabled, emptyMap<String, String>(), out)
            }
        }
        val serversList = settingsMap?.get("servers") as? List<*>
        if (serversList != null) {
            for (sItem in serversList) {
                val sMap = sItem as? Map<*, *> ?: continue
                val addr = jsonStr(sMap["address"]) ?: jsonStr(sMap["server"]) ?: continue
                val port = jsonPort(sMap["port"]) ?: jsonPort(sMap["server_port"]) ?: continue
                if (addr == "127.0.0.1" || addr == "0.0.0.0") continue
                val secret = jsonStr(sMap["password"]) ?: jsonStr(sMap["secret"]) ?: ""
                val method = jsonStr(sMap["method"]) ?: ""
                val scheme = protoType ?: "trojan"
                buildJsonShareUri(scheme, addr, port, secret, "", method, sni, net, tagStr, tlsEnabled, sMap, out)
            }
        }

        // Direct Sing-Box style outbound fields at current object level
        val directHost = jsonStr(obj["server"]) ?: jsonStr(obj["address"]) ?: return
        val directPort = jsonPort(obj["server_port"]) ?: jsonPort(obj["port"]) ?: return
        if (directHost == "127.0.0.1" || directHost == "0.0.0.0") return
        val effectiveType = protoType ?: inferSchemeFromJsonMap(obj)
        val secret = jsonStr(obj["uuid"])
            ?: jsonStr(obj["id"])
            ?: jsonStr(obj["password"])
            ?: jsonStr(obj["auth_str"])
            ?: jsonStr(obj["auth"])
            ?: jsonStr(obj["private_key"])
            ?: ""
        val user = jsonStr(obj["username"]) ?: ""
        val method = jsonStr(obj["method"]) ?: jsonStr(obj["cipher"]) ?: ""
        buildJsonShareUri(effectiveType, directHost, directPort, secret, user, method, sni, net, tagStr, tlsEnabled, obj, out)
    }

    private fun buildJsonShareUri(
        rawType: String,
        host: String,
        port: Int,
        secret: String,
        username: String,
        method: String,
        sni: String,
        network: String,
        tag: String,
        tlsEnabled: Boolean,
        extra: Map<*, *>,
        out: LinkedHashSet<String>
    ) {
        val h = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
        val frag = urlEncode(tag)
        val tok = secret.ifBlank { "dastyab" }
        val userAuth = when {
            username.isNotBlank() && secret.isNotBlank() -> "${urlEncode(username)}:${urlEncode(secret)}@"
            username.isNotBlank() -> "${urlEncode(username)}@"
            secret.isNotBlank() -> "${urlEncode(secret)}@"
            else -> ""
        }
        val uri = when (rawType.lowercase()) {
            "vless" -> {
                val qp = buildList {
                    add("type=${urlEncode(network.ifBlank { "tcp" })}")
                    if (sni.isNotBlank()) add("sni=${urlEncode(sni)}")
                    if (tlsEnabled) add("security=tls")
                }.joinToString("&")
                "vless://${urlEncode(tok)}@$h:$port?$qp#$frag"
            }
            "vmess" -> {
                val aid = jsonPort(extra["alter_id"])?.toString() ?: "0"
                val net = network.ifBlank { "tcp" }
                val vJson = """{"v":"2","ps":"${jsonEscape(tag)}","add":"${jsonEscape(host)}","port":"$port","id":"${jsonEscape(tok)}","aid":"$aid","net":"${jsonEscape(net)}","type":"none","tls":"${if (tlsEnabled) "tls" else ""}","sni":"${jsonEscape(sni)}"}"""
                "vmess://${encodeBase64UrlSafe(vJson)}"
            }
            "trojan" -> "trojan://${urlEncode(tok)}@$h:$port" +
                (if (sni.isNotBlank()) "?sni=${urlEncode(sni)}" else "") + "#$frag"
            "shadowsocks", "ss" -> {
                val m = method.ifBlank { "aes-256-gcm" }
                "ss://${urlEncode(m)}:${urlEncode(tok)}@$h:$port#$frag"
            }
            "shadowsocksr", "ssr" -> {
                val m = method.ifBlank { "aes-256-cfb" }
                val ssrProto = jsonStr(extra["protocol"]) ?: "origin"
                val obfs = jsonStr(extra["obfs"]) ?: "plain"
                val raw = "$host:$port:$ssrProto:$m:$obfs:${encodeBase64UrlSafe(tok)}"
                "ssr://${encodeBase64UrlSafe(raw)}#$frag"
            }
            "hysteria2", "hy2" -> "hy2://${urlEncode(tok)}@$h:$port" +
                (if (sni.isNotBlank()) "?sni=${urlEncode(sni)}" else "") + "#$frag"
            "hysteria" -> {
                val qp = buildList {
                    if (sni.isNotBlank()) add("sni=${urlEncode(sni)}")
                    if (secret.isNotBlank()) add("auth=${urlEncode(secret)}")
                }.joinToString("&")
                "hysteria://$h:$port" + (if (qp.isNotEmpty()) "?$qp" else "") + "#$frag"
            }
            "tuic" -> {
                val uid = jsonStr(extra["uuid"]) ?: tok
                val pw = jsonStr(extra["password"]) ?: tok
                "tuic://${urlEncode(uid)}:${urlEncode(pw)}@$h:$port" +
                    (if (sni.isNotBlank()) "?sni=${urlEncode(sni)}" else "") + "#$frag"
            }
            "juicity" -> {
                val uid = jsonStr(extra["uuid"]) ?: tok
                val pw = jsonStr(extra["password"]) ?: tok
                "juicity://${urlEncode(uid)}:${urlEncode(pw)}@$h:$port" +
                    (if (sni.isNotBlank()) "?sni=${urlEncode(sni)}" else "") + "#$frag"
            }
            "anytls" -> "anytls://${urlEncode(tok)}@$h:$port" +
                (if (sni.isNotBlank()) "?sni=${urlEncode(sni)}" else "") + "#$frag"
            "naive", "naive+https", "naive+quic" -> {
                val scheme = if (rawType.equals("naive+quic", true)) "naive+quic" else "naive+https"
                "$scheme://$userAuth$h:$port" +
                    (if (sni.isNotBlank()) "?sni=${urlEncode(sni)}" else "") + "#$frag"
            }
            "wireguard", "wg", "warp" -> {
                val pk = jsonStr(extra["peer_public_key"]) ?: jsonStr(extra["public_key"]) ?: ""
                val priv = jsonStr(extra["private_key"]) ?: secret
                val auth = if (priv.isNotBlank()) "${urlEncode(priv)}@" else ""
                val qp = if (pk.isNotBlank()) "?publickey=${urlEncode(pk)}" else ""
                "wireguard://$auth$h:$port$qp#$frag"
            }
            "socks", "socks5" -> "socks5://$userAuth$h:$port#$frag"
            "http" -> "${if (tlsEnabled) "https" else "http"}://$userAuth$h:$port#$frag"
            "https" -> "https://$userAuth$h:$port#$frag"
            else -> "trojan://${urlEncode(tok)}@$h:$port#$frag"
        }
        if (parse(uri) != null) out.add(uri)
    }

    private fun inferSchemeFromJsonMap(obj: Map<*, *>): String {
        val text = obj.keys.joinToString(",") { it.toString().lowercase() }
        return when {
            "private_key" in text || "peer_public_key" in text -> "wireguard"
            "auth_str" in text || "up_mbps" in text -> "hysteria"
            "method" in text && "password" in text -> "ss"
            "uuid" in text && "password" in text -> "tuic"
            "uuid" in text -> "vless"
            else -> "trojan"
        }
    }

    private fun extractFallbackJsonObject(obj: String, out: LinkedHashSet<String>) {
        val add = extractJsonString(obj, "add")
        if (add != null && (extractJsonString(obj, "id") != null || extractJsonString(obj, "v") != null)) {
            val port = extractJsonPort(obj, "port")
            if (port != null && add != "127.0.0.1" && add != "0.0.0.0") {
                val vmessUri = "vmess://${encodeBase64UrlSafe(obj)}"
                if (parse(vmessUri) != null) out.add(vmessUri)
                return
            }
        }
        val host = extractJsonString(obj, "server") ?: extractJsonString(obj, "address") ?: return
        val port = extractJsonPort(obj, "server_port") ?: extractJsonPort(obj, "port") ?: return
        if (host == "127.0.0.1" || host == "0.0.0.0") return
        val objLower = obj.lowercase()
        val scheme = when {
            objLower.contains("\"wireguard\"") || objLower.contains("\"warp\"") -> "wireguard"
            objLower.contains("\"hysteria2\"") -> "hy2"
            objLower.contains("\"hysteria\"") -> "hysteria"
            objLower.contains("\"vless\"") -> "vless"
            objLower.contains("\"trojan\"") -> "trojan"
            objLower.contains("\"tuic\"") -> "tuic"
            objLower.contains("\"juicity\"") -> "juicity"
            objLower.contains("\"anytls\"") -> "anytls"
            objLower.contains("\"naive\"") -> "naive+https"
            objLower.contains("\"shadowsocks\"") -> "ss"
            objLower.contains("\"socks\"") -> "socks5"
            objLower.contains("\"https\"") -> "https"
            objLower.contains("\"http\"") -> "http"
            else -> "trojan"
        }
        val h = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
        val idOrPass = extractJsonString(obj, "id")
            ?: extractJsonString(obj, "uuid")
            ?: extractJsonString(obj, "password")
            ?: "dastyab"
        val tag = urlEncode(extractJsonString(obj, "tag") ?: extractJsonString(obj, "ps") ?: "JSON-$scheme")
        val uri = when (scheme) {
            "wireguard", "socks5", "http", "https" -> "$scheme://$h:$port#$tag"
            "ss" -> "ss://aes-256-gcm:${urlEncode(idOrPass)}@$h:$port#$tag"
            else -> "$scheme://${urlEncode(idOrPass)}@$h:$port#$tag"
        }
        if (parse(uri) != null) out.add(uri)
    }

    private fun scanBalancedJsonObjects(text: String, maxObjects: Int = 256): List<String> {
        val result = ArrayList<String>()
        var i = 0
        val n = text.length
        while (i < n && result.size < maxObjects) {
            if (text[i] != '{') {
                i++
                continue
            }
            var depth = 0
            var inString = false
            var escaped = false
            var j = i
            val limit = (i + 32768).coerceAtMost(n)
            var matched = false
            while (j < limit) {
                val c = text[j]
                if (inString) {
                    if (escaped) {
                        escaped = false
                    } else if (c == '\\') {
                        escaped = true
                    } else if (c == '"') {
                        inString = false
                    }
                } else {
                    when (c) {
                        '"' -> inString = true
                        '{' -> depth++
                        '}' -> {
                            depth--
                            if (depth == 0) {
                                result.add(text.substring(i, j + 1))
                                matched = true
                                break
                            }
                        }
                    }
                }
                j++
            }
            i = if (matched) j + 1 else i + 1
        }
        return result
    }

    private fun parseJsonValue(input: String): Any? {
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
                        val key = parseString() ?: return null
                        skipWs()
                        if (pos >= len || input[pos] != ':') return null
                        pos++
                        val value = parseValue()
                        map[key] = value
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

        return parseValue()
    }

    private fun jsonStr(value: Any?): String? = when (value) {
        is String -> value.trim().takeIf { it.isNotEmpty() }
        is Number -> value.toString()
        else -> null
    }

    private fun jsonPort(value: Any?): Int? = when (value) {
        is Number -> value.toInt().takeIf { it in 1..65535 }
        is String -> value.trim().toIntOrNull()?.takeIf { it in 1..65535 }
        else -> null
    }

    private fun jsonEscape(value: String): String {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")
    }

    /** Converts an `openvpn://` / `ovpn://` URI back into a minimal client `.ovpn` profile. */
    fun openVpnUriToOvpn(uri: String): String? {
        val parsed = parse(uri) ?: return null
        if (parsed.protocol !in setOf("openvpn", "ovpn")) return null
        val params = parseQueryParams(uri.substringAfter('?', "").substringBefore('#'))
        val proto = params["proto"]?.takeIf { it.isNotBlank() } ?: "udp"
        val dev = params["dev"]?.takeIf { it.isNotBlank() } ?: "tun"
        val cipher = params["cipher"]?.takeIf { it.isNotBlank() }
        return buildString {
            appendLine("client")
            appendLine("dev $dev")
            appendLine("proto $proto")
            appendLine("remote ${parsed.host} ${parsed.port}")
            appendLine("resolv-retry infinite")
            appendLine("nobind")
            appendLine("persist-key")
            appendLine("persist-tun")
            if (cipher != null) appendLine("data-ciphers $cipher")
            appendLine("remote-cert-tls server")
            append("verb 3")
        }
    }

    /**
     * Scans raw text for WireGuard `.conf` INI blocks (`[Interface] ... [Peer]`) and converts each
     * valid block into a canonical `wireguard://` share URI so it can be stored, benchmarked, and
     * exported back to `.conf` cleanly.
     */
    fun extractWireGuardIniBlocks(rawText: String): List<String> {
        if (!rawText.contains("[Interface]", ignoreCase = true) ||
            !rawText.contains("[Peer]", ignoreCase = true)
        ) {
            return emptyList()
        }
        val out = LinkedHashSet<String>()
        val normalized = rawText.replace("\r\n", "\n").replace('\r', '\n')
        val sections = normalized.split(Regex("(?=\\[Interface\\])", RegexOption.IGNORE_CASE))
        for (block in sections) {
            if (!block.contains("[Interface]", ignoreCase = true) ||
                !block.contains("[Peer]", ignoreCase = true)
            ) continue
            val uri = wireGuardIniToUri(block)
            if (uri != null) out.add(uri)
        }
        return out.toList()
    }

    /** Converts a WireGuard `.conf` INI snippet (`[Interface]` + `[Peer]`) into `wireguard://...`. */
    fun wireGuardIniToUri(iniText: String, label: String = "WireGuard"): String? {
        var inInterface = false
        var inPeer = false
        var privateKey = ""
        var address = ""
        var dns = ""
        var mtu = ""
        var publicKey = ""
        var presharedKey = ""
        var endpoint = ""
        var reserved = ""

        for (rawLine in iniText.lines()) {
            val line = rawLine.substringBefore('#').trim()
            if (line.isEmpty()) continue
            when {
                line.equals("[Interface]", ignoreCase = true) -> {
                    inInterface = true
                    inPeer = false
                    continue
                }
                line.equals("[Peer]", ignoreCase = true) -> {
                    if (inPeer && endpoint.isNotBlank() && publicKey.isNotBlank()) break
                    inInterface = false
                    inPeer = true
                    continue
                }
                line.startsWith("[") -> {
                    inInterface = false
                    inPeer = false
                    continue
                }
            }
            val eqIdx = line.indexOf('=')
            if (eqIdx <= 0) continue
            val key = line.substring(0, eqIdx).trim().lowercase()
            val value = line.substring(eqIdx + 1).trim()
            if (value.isEmpty()) continue

            if (inInterface) {
                when (key) {
                    "privatekey" -> privateKey = value
                    "address" -> address = value
                    "dns" -> dns = value
                    "mtu" -> mtu = value
                    "reserved" -> reserved = value
                }
            } else if (inPeer) {
                when (key) {
                    "publickey" -> publicKey = value
                    "presharedkey" -> presharedKey = value
                    "endpoint" -> endpoint = value
                    "reserved" -> if (reserved.isBlank()) reserved = value
                }
            }
        }

        if (privateKey.isBlank() || publicKey.isBlank() || endpoint.isBlank()) return null
        val (host, port) = splitHostPort(endpoint) ?: return null
        val formattedHost = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host

        val queryParts = mutableListOf<String>()
        queryParts.add("publickey=${urlEncode(publicKey)}")
        if (address.isNotBlank()) queryParts.add("address=${urlEncode(address)}")
        if (dns.isNotBlank()) queryParts.add("dns=${urlEncode(dns)}")
        if (mtu.isNotBlank()) queryParts.add("mtu=${urlEncode(mtu)}")
        if (presharedKey.isNotBlank()) queryParts.add("presharedkey=${urlEncode(presharedKey)}")
        if (reserved.isNotBlank()) queryParts.add("reserved=${urlEncode(reserved)}")

        val frag = urlEncode(label.ifBlank { "WireGuard-$host" })
        return "wireguard://${urlEncode(privateKey)}@$formattedHost:$port?${queryParts.joinToString("&")}#$frag"
    }

    /** Converts a `wireguard://` / `wg://` / `warp://` share URI back into standard `.conf` INI format. */
    fun wireGuardUriToIni(uri: String): String? {
        val trimmed = uri.trim()
        val proto = protocolOf(trimmed)
        if (proto !in setOf("wireguard", "wg", "warp", "amneziawg")) return null
        val rest = trimmed.substringAfter("://").substringBefore('#')
        val userAndEndpoint = rest.substringBefore('?')
        val queryStr = rest.substringAfter('?', "")
        val (userPart, hostPortPart) = if (userAndEndpoint.contains('@')) {
            userAndEndpoint.substringBefore('@') to userAndEndpoint.substringAfter('@')
        } else {
            "" to userAndEndpoint
        }
        val (host, port) = splitHostPort(hostPortPart) ?: return null
        val params = parseQueryParams(queryStr)
        val privateKey = decodePercent(userPart).ifBlank { params["privatekey"].orEmpty() }
        val publicKey = params["publickey"] ?: params["pk"] ?: ""
        val address = params["address"] ?: "172.16.0.2/32"
        val dns = params["dns"] ?: "1.1.1.1"
        val mtu = params["mtu"] ?: "1280"
        val psk = params["presharedkey"] ?: params["psk"] ?: ""
        val reserved = params["reserved"] ?: ""
        val endpointHost = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host

        return buildString {
            appendLine("[Interface]")
            if (privateKey.isNotBlank()) appendLine("PrivateKey = $privateKey")
            appendLine("Address = $address")
            appendLine("DNS = $dns")
            appendLine("MTU = $mtu")
            if (reserved.isNotBlank()) appendLine("Reserved = $reserved")
            appendLine()
            appendLine("[Peer]")
            if (publicKey.isNotBlank()) appendLine("PublicKey = $publicKey")
            if (psk.isNotBlank()) appendLine("PresharedKey = $psk")
            appendLine("AllowedIPs = 0.0.0.0/0, ::/0")
            append("Endpoint = $endpointHost:$port")
        }
    }

    fun protocolOf(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.contains("[Interface]", ignoreCase = true) &&
            trimmed.contains("[Peer]", ignoreCase = true)
        ) {
            return "wireguard"
        }
        if (trimmed.contains("remote ", ignoreCase = true) &&
            (trimmed.contains("\nclient", ignoreCase = true) ||
                trimmed.startsWith("client", ignoreCase = true) ||
                trimmed.contains("dev tun", ignoreCase = true) ||
                trimmed.contains("<ca>", ignoreCase = true))
        ) {
            return "openvpn"
        }
        if (trimmed.startsWith("tg://proxy?", ignoreCase = true) ||
            Regex("^https?://(?:t\\.me|telegram\\.me)/proxy\\?", RegexOption.IGNORE_CASE).containsMatchIn(trimmed)
        ) {
            return "mtproto"
        }
        if (trimmed.startsWith("tg://socks?", ignoreCase = true) ||
            Regex("^https?://(?:t\\.me|telegram\\.me)/socks\\?", RegexOption.IGNORE_CASE).containsMatchIn(trimmed)
        ) {
            return "socks5"
        }
        val idx = trimmed.indexOf("://")
        return if (idx > 0) trimmed.substring(0, idx).lowercase() else "unknown"
    }

    fun familyOf(protocol: String): Family = when (protocol.lowercase()) {
        "wireguard", "wg", "warp", "amneziawg" -> Family.WIREGUARD
        "openvpn", "ovpn" -> Family.OPENVPN
        "npv", "npv4", "npvs", "npvt", "napsternetv" -> Family.NAPSTERNETV
        "mtproto" -> Family.TELEGRAM_MTPROTO
        "socks", "socks4", "socks5", "http", "https", "ssh", "sn", "dnstt", "slipnet" -> Family.PROXY_TUNNEL
        else -> Family.XRAY_SINGBOX
    }

    /** Canonicalizes protocol aliases (`hy2`->`hysteria2`, `wg`->`wireguard`, `socks`->`socks5`, `ovpn`->`openvpn`). */
    fun canonicalProtocol(protocol: String): String = when (protocol.trim().lowercase()) {
        "hy2" -> "hysteria2"
        "wg" -> "wireguard"
        "socks" -> "socks5"
        "ovpn" -> "openvpn"
        else -> protocol.trim().lowercase()
    }

    /** Normalizes a share link (trimmed, HTML-unescaped, normalized host casing) for dedup and storage. */
    fun normalizeUri(raw: String): String = unescapeHtml(raw).trim()

    /** Computes canonical deduplication key `protocol:host:port:id`. */
    fun dedupKey(raw: String): String {
        val ep = parse(raw) ?: return normalizeUri(raw)
        return "${canonicalProtocol(ep.protocol)}:${ep.host.lowercase()}:${ep.port}:${ep.id}"
    }

    /** Deduplicates parsed/raw configs by `protocol+host+port+id`, preserving first-seen order. */
    fun deduplicate(configs: Collection<String>): List<String> {
        if (configs.isEmpty()) return emptyList()
        val seen = LinkedHashMap<String, String>(configs.size)
        for (raw in configs) {
            val clean = normalizeUri(raw)
            if (clean.isEmpty()) continue
            val key = dedupKey(clean)
            seen.putIfAbsent(key, clean)
        }
        return seen.values.toList()
    }

    fun isWireGuardUri(uri: String): Boolean {
        val proto = protocolOf(uri)
        return proto in setOf("wireguard", "wg", "warp", "amneziawg")
    }

    fun isOpenVpnUri(uri: String): Boolean {
        val proto = protocolOf(uri)
        return proto in setOf("openvpn", "ovpn")
    }

    fun isMtProtoUri(uri: String): Boolean = protocolOf(uri) == "mtproto"

    /** Parses ANY supported share-link, WireGuard INI, or OpenVPN snippet into a structured endpoint. */
    fun parse(raw: String?): ParsedEndpoint? {
        val trimmed = raw?.trim().orEmpty()
        if (trimmed.isEmpty()) return null

        // Raw WireGuard INI snippet pasted directly
        if (trimmed.contains("[Interface]", ignoreCase = true) &&
            trimmed.contains("[Peer]", ignoreCase = true)
        ) {
            val converted = wireGuardIniToUri(trimmed) ?: return null
            return parse(converted)
        }

        // Raw OpenVPN .ovpn text pasted directly
        if (protocolOf(trimmed) == "openvpn" && !trimmed.contains("://")) {
            val converted = extractOpenVpnConfigs(trimmed).firstOrNull() ?: return null
            return parse(converted)
        }

        val proto = protocolOf(trimmed)
        if (proto !in SUPPORTED_PROTOCOLS) return null

        if (proto in setOf("http", "https") && isNonProxyHttpUrl(trimmed)) return null

        // VLESS
        if (proto == "vless") {
            val vless = TunnelConfig.parseVlessUri(trimmed) ?: return null
            return ParsedEndpoint(trimmed, "vless", Family.XRAY_SINGBOX, vless.host, vless.port, vless.label, vless.uuid)
        }

        // Telegram MTProto proxy links
        if (proto == "mtproto") {
            return parseMtProto(trimmed)
        }

        // Telegram SOCKS5 share links (tg://socks?server=...&port=...&user=...&pass=...)
        if (proto == "socks5" && (trimmed.startsWith("tg://socks?", ignoreCase = true) ||
                Regex("^https?://(?:t\\.me|telegram\\.me)/socks\\?", RegexOption.IGNORE_CASE).containsMatchIn(trimmed))
        ) {
            val hop = TunnelConfig.parseProxyHop(trimmed) ?: return null
            val id = if (hop.username.isNotBlank() || hop.password.isNotBlank()) "${hop.username}:${hop.password}" else "${hop.host}:${hop.port}"
            return ParsedEndpoint(trimmed, "socks5", Family.PROXY_TUNNEL, hop.host, hop.port, "Telegram SOCKS5", id)
        }

        // VMess Base64(JSON)
        if (proto == "vmess") {
            val payload = trimmed.substringAfter("://").substringBefore('#').substringBefore('?')
            val json = tryDecodeBase64(payload) ?: return null
            val host = extractJsonString(json, "add") ?: extractJsonString(json, "host") ?: return null
            val port = extractJsonPort(json, "port") ?: return null
            val label = extractJsonString(json, "ps").orEmpty()
            val id = extractJsonString(json, "id").orEmpty()
            return ParsedEndpoint(trimmed, "vmess", Family.XRAY_SINGBOX, host, port, label, id)
        }

        // SSR Base64(host:port:proto:method:obfs:pass/...)
        if (proto == "ssr") {
            val payload = trimmed.substringAfter("://").substringBefore('#')
            val decoded = tryDecodeBase64(payload) ?: return null
            val head = decoded.substringBefore('/')
            val (host, port) = splitHostPort(head.split(':').take(2).joinToString(":"))
                ?: head.split(':').takeIf { it.size >= 2 }?.let { parts ->
                    val p = parts[1].toIntOrNull()
                    if (parts[0].isNotBlank() && p != null && p in 1..65535) parts[0] to p else null
                } ?: return null
            val label = trimmed.substringAfter('#', "").let { decodePercent(it) }
            val parts = head.split(':')
            val id = parts.getOrNull(5)?.trim().orEmpty()
            return ParsedEndpoint(trimmed, "ssr", Family.XRAY_SINGBOX, host, port, label, id)
        }

        // Shadowsocks (plain, SIP002, or whole-URI Base64)
        if (proto == "ss") {
            val noFrag = trimmed.substringAfter("://").substringBefore('#')
            val label = trimmed.substringAfter('#', "").let { decodePercent(it) }
            var id = ""
            val hostPortPair = if (noFrag.contains('@')) {
                val rawUser = noFrag.substringBefore('@')
                val decodedUser = tryDecodeBase64(rawUser) ?: decodePercent(rawUser)
                id = decodedUser
                splitHostPort(noFrag.substringAfter('@').substringBefore('?').substringBefore('/'))
            } else {
                val b64 = noFrag.substringBefore('?')
                val decoded = tryDecodeBase64(b64) ?: return null
                if (!decoded.contains('@')) return null
                id = decoded.substringBefore('@')
                splitHostPort(decoded.substringAfter('@').substringBefore('?').substringBefore('/'))
            } ?: return null
            return ParsedEndpoint(trimmed, "ss", Family.XRAY_SINGBOX, hostPortPair.first, hostPortPair.second, label, id)
        }

        // NapsternetV (`npv://`, `npv4://`, `npvs://`, `npvt://`, `napsternetv://`)
        if (proto in setOf("npv", "npv4", "npvs", "npvt", "napsternetv")) {
            val label = trimmed.substringAfter('#', "").let { decodePercent(it) }
            val body = trimmed.substringAfter("://").substringBefore('#')
            val authoritySegment = body.substringBefore('?').substringBefore('/')
            if (authoritySegment.contains('@') || authoritySegment.contains(':')) {
                val userPart = if (authoritySegment.contains('@')) decodePercent(authoritySegment.substringBefore('@')) else ""
                val hostPortPart = if (authoritySegment.contains('@')) {
                    authoritySegment.substringAfterLast('@')
                } else {
                    authoritySegment
                }
                val direct = splitHostPort(hostPortPart)
                if (direct != null) {
                    return ParsedEndpoint(trimmed, proto, Family.NAPSTERNETV, direct.first, direct.second, label, userPart)
                }
            }
            val decoded = tryDecodeBase64(body.substringBefore('?'))
            if (decoded != null) {
                // Nested link inside npv4/npv/npvs base64
                if (decoded.contains("://")) {
                    val inner = parse(decoded)
                    if (inner != null) {
                        return ParsedEndpoint(trimmed, proto, Family.NAPSTERNETV, inner.host, inner.port, inner.label.ifBlank { label }, inner.id)
                    }
                }
                val host = extractJsonString(decoded, "add")
                    ?: extractJsonString(decoded, "host")
                    ?: extractJsonString(decoded, "server")
                    ?: extractJsonString(decoded, "address")
                val port = extractJsonPort(decoded, "port")
                    ?: extractJsonPort(decoded, "serverPort")
                    ?: 443
                if (!host.isNullOrBlank()) {
                    val ps = extractJsonString(decoded, "ps")
                        ?: extractJsonString(decoded, "remarks")
                        ?: extractJsonString(decoded, "remark")
                        ?: extractJsonString(decoded, "name")
                        ?: extractJsonString(decoded, "tag")
                        ?: label
                    val id = extractJsonString(decoded, "id") ?: extractJsonString(decoded, "uuid") ?: ""
                    return ParsedEndpoint(trimmed, proto, Family.NAPSTERNETV, host, port, ps, id)
                }
            }
            val authorityHostPort = parseAuthorityHostPort(trimmed)
            if (authorityHostPort != null) {
                return ParsedEndpoint(trimmed, proto, Family.NAPSTERNETV, authorityHostPort.first, authorityHostPort.second, label)
            }
            return null
        }

        // Standard authority URIs (trojan, hy2, hysteria2, hysteria, tuic, juicity, anytls, naive+*, wireguard, wg, warp, openvpn, ovpn, socks*, http, https, ssh, sn, dnstt, slipnet)
        val hp = parseAuthorityHostPort(trimmed) ?: return null
        val label = trimmed.substringAfter('#', "").let { decodePercent(it) }
        val userInfo = trimmed.substringAfter("://")
            .substringBefore('#')
            .substringBefore('?')
            .substringBefore('/')
            .let { if (it.contains('@')) decodePercent(it.substringBeforeLast('@')) else "" }
        val queryParams = parseQueryParams(trimmed.substringAfter('?', "").substringBefore('#'))
        val id = when {
            userInfo.isNotEmpty() -> userInfo
            proto == "hysteria" -> queryParams["auth"] ?: queryParams["auth_str"] ?: ""
            proto in setOf("wireguard", "wg", "warp", "amneziawg") -> queryParams["privatekey"] ?: ""
            else -> ""
        }
        return ParsedEndpoint(trimmed, proto, familyOf(proto), hp.first, hp.second, label, id)
    }

    fun extractHostAndPort(raw: String): Pair<String, Int>? {
        return parse(raw)?.let { it.host to it.port }
    }

    fun isPlausible(uri: String): Boolean {
        if (uri.length < 14 || uri.length > 4096) return false
        return parse(uri) != null
    }

    fun priorityRank(uri: String): Int = when (protocolOf(uri)) {
        "vless" -> 0
        "trojan" -> 1
        "hy2", "hysteria2", "hysteria" -> 2
        "tuic" -> 3
        "wireguard", "wg", "warp", "amneziawg" -> 4
        "openvpn", "ovpn" -> 5
        "vmess" -> 6
        "ss", "ssr" -> 7
        "npv4", "npvs", "npvt", "npv", "napsternetv" -> 8
        "juicity", "anytls", "naive+https", "naive+quic", "naive" -> 9
        "socks5", "socks", "socks4", "http", "https", "ssh", "sn", "dnstt", "slipnet" -> 10
        "mtproto" -> 11
        else -> 15
    }

    /**
     * Picks up to [limit] configs while preserving protocol diversity across all harvested sources
     * (prevents e.g. 120 VLESS links from crowding out harvested WireGuard, NapsternetV, or MTProto configs).
     */
    fun mergeBalanced(configs: Collection<String>, limit: Int = 4096): List<String> {
        if (configs.isEmpty()) return emptyList()
        val deduped = deduplicate(configs)
        val grouped = deduped.groupBy { canonicalProtocol(protocolOf(it)) }
        val result = LinkedHashSet<String>()

        // Round 1: guarantee representation from every harvested protocol in priority order
        val orderedProtocols = grouped.keys.sortedBy { proto ->
            grouped[proto]?.firstOrNull()?.let { priorityRank(it) } ?: 99
        }
        val queues = orderedProtocols.associateWith { ArrayDeque(grouped[it].orEmpty()) }
        var added = true
        while (result.size < limit && added) {
            added = false
            for (proto in orderedProtocols) {
                val q = queues[proto] ?: continue
                if (q.isNotEmpty()) {
                    result.add(q.removeFirst())
                    added = true
                    if (result.size >= limit) break
                }
            }
        }
        return result.sortedWith(compareBy<String> { priorityRank(it) }.thenBy { it.length })
    }

    /** Extracts chainable SOCKS5 / HTTP proxy hops from harvested URIs for multi-layer stacking. */
    fun extractChainableProxyHops(
        configs: Collection<String>,
        limit: Int = Int.MAX_VALUE
    ): List<TunnelConfig.ProxyHop> {
        val out = LinkedHashMap<String, TunnelConfig.ProxyHop>()
        for (raw in configs) {
            if (out.size >= limit) break
            val proto = protocolOf(raw)
            if (proto in setOf("socks5", "socks", "http")) {
                val hop = TunnelConfig.parseProxyHop(raw) ?: continue
                if (hop.scheme != TunnelConfig.ProxyScheme.DIRECT) {
                    out.putIfAbsent("${hop.scheme.name}:${hop.host}:${hop.port}", hop)
                }
            }
        }
        return out.values.toList()
    }

    private val PROXY_SCHEME_LINE_REGEX = Regex(
        """(?<![A-Za-z0-9+.-])(?:socks5|socks|http)://(?:[^\s"'<>`\\]+@)?(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):(\d{1,5})(?=[\s"'<>`,;|#\r\n]|$)""",
        RegexOption.IGNORE_CASE
    )
    private val BARE_IPV4_PORT_REGEX = Regex(
        """(?<![A-Za-z0-9_./:@-])(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?![.\d/])"""
    )
    private val ANY_SCHEME_URI_REGEX = Regex("""[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>`\\]+""")

    /**
     * Extracts chainable SOCKS5 / HTTP proxy hops from raw proxy-list feeds, HTML pages,
     * `tg://socks` links, explicit `socks5://` / `http://ip:port` URIs, or bare `IPv4:port` lines,
     * returning a `/16`-subnet-diverse list capped at [maxHops].
     */
    fun extractProxyListHops(
        rawPayload: String,
        defaultScheme: TunnelConfig.ProxyScheme = TunnelConfig.ProxyScheme.SOCKS5,
        maxHops: Int = 250
    ): List<TunnelConfig.ProxyHop> {
        if (rawPayload.isBlank()) return emptyList()
        val unescaped = unescapeHtml(rawPayload)
        val texts = mutableListOf(unescaped)
        tryDecodeBase64(unescaped)?.let { decoded ->
            if (decoded.contains(':') || decoded.contains("://")) {
                texts.add(decoded)
            }
        }

        val out = LinkedHashMap<String, TunnelConfig.ProxyHop>()
        fun addHop(hop: TunnelConfig.ProxyHop?) {
            if (hop == null || hop.scheme == TunnelConfig.ProxyScheme.DIRECT) return
            if (hop.port !in 1..65535 || hop.host.isBlank()) return
            val normHost = hop.host.trim().removePrefix("[").removeSuffix("]").lowercase()
            if (normHost.startsWith("0.") || normHost.startsWith("127.") || normHost == "::" || TunnelConfig.isLoopbackHost(normHost)) return
            out.putIfAbsent("${hop.scheme.name}:${hop.host}:${hop.port}", hop)
        }

        for (text in texts) {
            val bareScanBuf = StringBuilder(text)
            fun blankRange(range: IntRange) {
                for (idx in range) {
                    if (idx in bareScanBuf.indices) bareScanBuf.setCharAt(idx, ' ')
                }
            }

            TG_SOCKS_URI_REGEX.findAll(text).forEach { m ->
                addHop(TunnelConfig.parseProxyHop(cleanUri(m.value)))
                blankRange(m.range)
            }
            PROXY_SCHEME_LINE_REGEX.findAll(text).forEach { m ->
                addHop(TunnelConfig.parseProxyHop(cleanUri(m.value)))
                blankRange(m.range)
            }
            ANY_SCHEME_URI_REGEX.findAll(text).forEach { m ->
                blankRange(m.range)
            }
            if (defaultScheme != TunnelConfig.ProxyScheme.DIRECT) {
                BARE_IPV4_PORT_REGEX.findAll(bareScanBuf).forEach { m ->
                    val ip = m.groupValues[1]
                    val port = m.groupValues[2].toIntOrNull()
                    if (port != null && port in 1..65535 && TunnelConfig.isValidIpv4(ip)) {
                        addHop(TunnelConfig.ProxyHop(defaultScheme, ip, port))
                    }
                }
            }
        }
        return selectDiverseProxyHops(out.values.toList(), limit = maxHops)
    }

    /** Returns `/16` prefix (`A.B`) for IPv4 hosts or normalized domain root so probes span different providers. */
    fun subnet16Of(host: String): String {
        val clean = host.trim().lowercase()
        if (TunnelConfig.isValidIpv4(clean)) {
            val parts = clean.split('.')
            if (parts.size >= 2) return "${parts[0]}.${parts[1]}"
        }
        return clean
    }

    /**
     * Picks up to [limit] hops using round-robin across `/16` subnets so a single blocked
     * datacenter range never monopolizes all probe slots.
     */
    fun selectDiverseProxyHops(
        hops: List<TunnelConfig.ProxyHop>,
        limit: Int,
        excludedHosts: Set<String> = emptySet(),
        excludedSubnets16: Set<String> = emptySet()
    ): List<TunnelConfig.ProxyHop> {
        if (hops.isEmpty() || limit <= 0) return emptyList()
        val deduped = hops
            .filter { it.scheme != TunnelConfig.ProxyScheme.DIRECT && it.host.isNotBlank() && it.port in 1..65535 }
            .filterNot { excludedHosts.contains(it.host) }
            .distinctBy { "${it.scheme.name}:${it.host}:${it.port}" }
        if (deduped.isEmpty()) return emptyList()

        // Prefer hops outside excluded /16 subnets first, then fallback to excluded subnets if needed
        val freshSubnets = deduped.filterNot { excludedSubnets16.contains(subnet16Of(it.host)) }
        val recycledSubnets = deduped.filter { excludedSubnets16.contains(subnet16Of(it.host)) }

        val result = ArrayList<TunnelConfig.ProxyHop>(limit.coerceAtMost(deduped.size))
        for (bucketSource in listOf(freshSubnets, recycledSubnets)) {
            if (bucketSource.isEmpty() || result.size >= limit) continue
            val buckets = LinkedHashMap<String, ArrayDeque<TunnelConfig.ProxyHop>>()
            for (h in bucketSource) {
                buckets.getOrPut(subnet16Of(h.host)) { ArrayDeque() }.addLast(h)
            }
            var madeProgress = true
            while (result.size < limit && madeProgress) {
                madeProgress = false
                for (q in buckets.values) {
                    if (q.isNotEmpty()) {
                        result.add(q.removeFirst())
                        madeProgress = true
                        if (result.size >= limit) break
                    }
                }
            }
        }
        return result
    }

    private fun parseAuthorityHostPort(uriStr: String): Pair<String, Int>? {
        val afterScheme = uriStr.substringAfter("://")
        val authorityAndPath = afterScheme.substringBefore('#').substringBefore('?').substringBefore('/')
        val hostPortStr = if (authorityAndPath.contains('@')) authorityAndPath.substringAfterLast('@') else authorityAndPath
        val direct = splitHostPort(hostPortStr)
        if (direct != null) return direct

        // Fallback via java.net.URI for valid RFC URIs with default port 443
        return try {
            val u = URI(uriStr)
            val h = u.host?.trim().orEmpty()
            if (h.isEmpty()) return null
            val p = if (u.port in 1..65535) u.port else defaultPortFor(protocolOf(uriStr))
            h to p
        } catch (_: Exception) {
            null
        }
    }

    private fun defaultPortFor(proto: String): Int = when (proto) {
        "ssh" -> 22
        "socks", "socks4", "socks5" -> 1080
        "wireguard", "wg", "warp", "amneziawg" -> 51820
        "openvpn", "ovpn" -> 1194
        else -> 443
    }

    private fun splitHostPort(raw: String): Pair<String, Int>? {
        val s = raw.trim()
        if (s.isEmpty()) return null
        if (s.startsWith("[")) {
            val close = s.indexOf(']')
            if (close <= 1) return null
            val host = s.substring(1, close).trim()
            val after = s.substring(close + 1)
            val port = if (after.startsWith(":")) after.substring(1).toIntOrNull() else null
            if (host.isEmpty() || port == null || port !in 1..65535) return null
            return host to port
        }
        val colon = s.lastIndexOf(':')
        if (colon <= 0) return null
        val host = s.substring(0, colon).trim()
        val port = s.substring(colon + 1).trim().toIntOrNull() ?: return null
        if (host.isEmpty() || port !in 1..65535 || host.any { it.isWhitespace() }) return null
        return host to port
    }

    private fun parseMtProto(trimmed: String): ParsedEndpoint? {
        val rawQuery = trimmed.substringAfter('?', "")
        val query = rawQuery.substringBefore('#')
        if (query.isBlank()) return null

        var server: String? = null
        var port: Int? = null
        var secret: String? = null

        for (pair in query.split('&')) {
            if (pair.isEmpty()) continue
            val idx = pair.indexOf('=')
            if (idx <= 0) return null
            val key = pair.substring(0, idx).trim().lowercase()
            val decoded = decodeQueryComponent(pair.substring(idx + 1).trim()) ?: return null
            when (key) {
                "server", "host" -> {
                    val value = decoded.trim()
                    if (server != null ||
                        value.isEmpty() ||
                        decoded.any { it.isWhitespace() } ||
                        value.contains('/') ||
                        value.contains('#') ||
                        value.contains('?')
                    ) {
                        return null
                    }
                    server = value
                }
                "port" -> {
                    if (port != null || decoded.isEmpty() || !decoded.all { it in '0'..'9' }) {
                        return null
                    }
                    val p = decoded.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
                    port = p
                }
                "secret" -> {
                    val value = decoded.trim()
                    if (secret != null || value.isEmpty() || decoded.any { it.isWhitespace() }) {
                        return null
                    }
                    secret = value
                }
                else -> return null
            }
        }

        val host = server ?: return null
        val validPort = port ?: return null
        if (secret == null) return null
        val label = rawQuery.substringAfter('#', "")
            .let { decodePercent(it).trim() }
            .ifBlank { "Telegram MTProto" }
        return ParsedEndpoint(trimmed, "mtproto", Family.TELEGRAM_MTPROTO, host, validPort, label, secret)
    }

    private fun parseQueryParams(query: String): Map<String, String> {
        if (query.isBlank()) return emptyMap()
        val map = mutableMapOf<String, String>()
        query.split('&').forEach { pair ->
            val idx = pair.indexOf('=')
            if (idx > 0) {
                map[pair.substring(0, idx).lowercase()] = decodePercent(pair.substring(idx + 1))
            }
        }
        return map
    }

    private fun extractJsonString(json: String, field: String): String? {
        val m = Regex(""""$field"\s*:\s*"([^"]*)"""").find(json) ?: return null
        return m.groupValues[1].trim().takeIf { it.isNotEmpty() }
    }

    private fun extractJsonPort(json: String, field: String): Int? {
        val m = Regex(""""$field"\s*:\s*"?(\d{1,5})"?""").find(json) ?: return null
        val port = m.groupValues[1].toIntOrNull() ?: return null
        return port.takeIf { it in 1..65535 }
    }

    private fun unescapeHtml(input: String): String {
        return input
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("<br/>", "\n")
            .replace("<br />", "\n")
            .replace("<br>", "\n")
    }

    /**
     * PattNG-style Entry -> Exit Xray chain config JSON builder (pure Kotlin, supports WARP/WireGuard,
     * SOCKS5, HTTP, VLESS, Trojan, Shadowsocks, Hysteria2 as Entry or Exit, plus TLS fragment & uTLS fingerprint).
     */
    fun buildXrayChainConfigJson(
        entryUri: String?,
        exitUri: String,
        socksPort: Int = 10808,
        fragment: String = "10-20,10-20,tlshello",
        fingerprint: String = "chrome"
    ): String {
        val exitParsed = parse(exitUri)
            ?: throw IllegalArgumentException("Unsupported exit URI: ${protocolOf(exitUri)}")
        val entryParsed = entryUri?.takeIf { it.isNotBlank() }?.let { parse(it) }
        val entryOutboundJson = entryParsed?.let { renderSingleOutboundJson("entry", it, null, fingerprint, fragment) }
        val dialerTag = if (entryOutboundJson != null) "entry" else if (fragment.isNotBlank()) "fragment" else null
        val exitOutboundJson = renderSingleOutboundJson("proxy", exitParsed, dialerTag, fingerprint, "")
        val fragmentOutboundJson = """{"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"$fragment","length":"10-20","interval":"10-20"}}}"""
        val outbounds = buildList {
            add(exitOutboundJson)
            if (entryOutboundJson != null) add(entryOutboundJson)
            if (fragment.isNotBlank()) add(fragmentOutboundJson)
            add("""{"tag":"direct","protocol":"freedom"}""")
        }.joinToString(",")
        return """{"log":{"loglevel":"warning"},"inbounds":[{"tag":"socks-in","port":$socksPort,"listen":"127.0.0.1","protocol":"socks","settings":{"udp":true}}],"outbounds":[$outbounds]}"""
    }

    private fun renderSingleOutboundJson(
        tag: String,
        ep: ParsedEndpoint,
        dialerProxy: String?,
        fingerprint: String,
        fragmentTag: String
    ): String {
        val proto = ep.protocol.lowercase()
        val host = ep.host.replace("\"", "")
        val port = ep.port
        val raw = ep.uri
        val params = parseQueryParams(raw.substringAfter('?', "").substringBefore('#'))
        val dialerJson = if (!dialerProxy.isNullOrBlank()) """"sockopt":{"dialerProxy":"$dialerProxy"}""" else if (fragmentTag.isNotBlank()) """"sockopt":{"dialerProxy":"fragment"}""" else ""
        val userPart = raw.substringAfter("://", "").substringBefore('@').substringBefore('?').substringBefore('#')
        val decodedUser = decodePercent(userPart).replace("\"", "")
        return when (proto) {
            "wireguard", "wg", "warp", "amneziawg" -> {
                val priv = decodedUser.ifBlank { params["privatekey"].orEmpty() }.replace("\"", "")
                val pub = (params["publickey"] ?: params["pk"] ?: "").replace("\"", "")
                val sockopt = if (dialerJson.isNotEmpty()) ""","streamSettings":{$dialerJson}""" else ""
                """{"tag":"$tag","protocol":"wireguard","settings":{"secretKey":"$priv","address":["172.16.0.2/32"],"peers":[{"publicKey":"$pub","endpoint":"$host:$port"}]}$sockopt}"""
            }
            "socks", "socks5", "socks4" -> {
                val sockopt = if (dialerJson.isNotEmpty()) ""","streamSettings":{$dialerJson}""" else ""
                """{"tag":"$tag","protocol":"socks","settings":{"servers":[{"address":"$host","port":$port}]}$sockopt}"""
            }
            "http" -> {
                val sockopt = if (dialerJson.isNotEmpty()) ""","streamSettings":{$dialerJson}""" else ""
                """{"tag":"$tag","protocol":"http","settings":{"servers":[{"address":"$host","port":$port}]}$sockopt}"""
            }
            "trojan" -> {
                val sni = (params["sni"] ?: host).replace("\"", "")
                val sockStr = if (dialerJson.isNotEmpty()) ",$dialerJson" else ""
                """{"tag":"$tag","protocol":"trojan","settings":{"servers":[{"address":"$host","port":$port,"password":"$decodedUser"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"$sni","fingerprint":"$fingerprint"}$sockStr}}"""
            }
            "hy2", "hysteria2", "hysteria" -> {
                val sni = (params["sni"] ?: host).replace("\"", "")
                val sockStr = if (dialerJson.isNotEmpty()) ",$dialerJson" else ""
                """{"tag":"$tag","protocol":"hysteria2","settings":{"servers":[{"address":"$host","port":$port,"password":"$decodedUser"}]},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"$sni","fingerprint":"$fingerprint"}$sockStr}}"""
            }
            "vless" -> {
                val sni = (params["sni"] ?: params["host"] ?: host).replace("\"", "")
                val sec = (params["security"] ?: "tls").replace("\"", "")
                val net = (params["type"] ?: "ws").replace("\"", "")
                val sockStr = if (dialerJson.isNotEmpty()) ",$dialerJson" else ""
                """{"tag":"$tag","protocol":"vless","settings":{"vnext":[{"address":"$host","port":$port,"users":[{"id":"$decodedUser","encryption":"none"}]}]},"streamSettings":{"network":"$net","security":"$sec","tlsSettings":{"serverName":"$sni","fingerprint":"$fingerprint"}$sockStr}}"""
            }
            else -> {
                val sockStr = if (dialerJson.isNotEmpty()) """"streamSettings":{$dialerJson},""" else ""
                """{"tag":"$tag","protocol":"$proto",$sockStr"settings":{"servers":[{"address":"$host","port":$port}]}}"""
            }
        }
    }

    private fun cleanUri(raw: String): String {
        return raw.trim().trimEnd(',', ';', '.', ')', ']', '}', '>', '\'', '"', '#')
    }

    private fun tryDecodeBase64(input: String): String? {
        val compact = input.filter { !it.isWhitespace() }
        if (compact.length < 12) return null
        return try {
            val bytes = decodeBase64Bytes(compact) ?: return null
            val text = String(bytes, Charsets.UTF_8)
            if (text.any { it.code < 9 && it != '\n' && it != '\r' && it != '\t' }) null else text
        } catch (_: Exception) {
            null
        }
    }

    private fun encodeBase64UrlSafe(input: String): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val bytes = input.toByteArray(Charsets.UTF_8)
        val out = StringBuilder(((bytes.size + 2) / 3) * 4)
        var i = 0
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xFF
            val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else 0
            val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else 0
            out.append(alphabet[b0 ushr 2])
            out.append(alphabet[((b0 and 0x03) shl 4) or (b1 ushr 4)])
            out.append(if (i + 1 < bytes.size) alphabet[((b1 and 0x0F) shl 2) or (b2 ushr 6)] else '=')
            out.append(if (i + 2 < bytes.size) alphabet[b2 and 0x3F] else '=')
            i += 3
        }
        return out.toString()
    }

    /** Pure-Kotlin RFC-4648 standard + URL-safe Base64 decoder (safe on API 24+ and plain JVM tests). */
    private fun decodeBase64Bytes(input: String): ByteArray? {
        val clean = input.trimEnd('=')
        if (clean.isEmpty()) return null
        val out = ArrayList<Byte>((clean.length * 3) / 4)
        var acc = 0
        var bits = 0
        for (ch in clean) {
            val v = when (ch) {
                in 'A'..'Z' -> ch.code - 'A'.code
                in 'a'..'z' -> ch.code - 'a'.code + 26
                in '0'..'9' -> ch.code - '0'.code + 52
                '+', '-' -> 62
                '/', '_' -> 63
                else -> return null
            }
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.add(((acc ushr bits) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }

    private fun decodeQueryComponent(value: String): String? =
        try {
            URLDecoder.decode(value.replace("+", "%2B"), "UTF-8")
        } catch (_: IllegalArgumentException) {
            null
        }

    private fun decodePercent(value: String): String {
        return decodeQueryComponent(value) ?: value
    }

    private fun urlEncode(value: String): String {
        return try {
            URLEncoder.encode(value, "UTF-8").replace("+", "%20")
        } catch (_: Exception) {
            value
        }
    }
}
