package com.dastyab.app

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.widget.Toast
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * ConfigHarvester — 5-stage resilient proxy/VPN config harvester designed for
 * heavily censored networks and blackout conditions:
 *
 *  Stage 1: GitHub Direct Raw + jsDelivr CDN mirrors (prioritized whenever GitHub is reachable)
 *  Stage 2: Telegram Public Channels (`t.me/s/<channel>`)
 *  Stage 3: Detect active/installed alternate VPNs (WhiteDNS, WhiteVPN, SlipNet, Lantern, Tor/Orbot, etc.)
 *  Stage 4: Guide user to configure a temporary base bootstrap config, connect, and re-harvest
 *  Stage 5: Emergency DNS Blackout VPN (DoH / WhiteDNS) + Clean IP Scout fallback
 */
object ConfigHarvester {

    data class FeedSource(
        val name: String,
        val primaryUrl: String,
        val mirrorUrl: String? = null,
        val kind: SourceKind,
        val defaultScheme: TunnelConfig.ProxyScheme = TunnelConfig.ProxyScheme.SOCKS5
    )

    enum class SourceKind { GITHUB, TELEGRAM }

    enum class HarvestOutcome {
        SUCCESS_GITHUB,
        SUCCESS_TELEGRAM,
        SUCCESS_MIXED,
        NEEDS_ALTERNATE_VPN,
        NEEDS_BOOTSTRAP_CONFIG,
        BLACKOUT_DNS_ONLY
    }

    data class FallbackTool(
        val name: String,
        val category: String,
        val packageNames: List<String>,
        val githubUrl: String,
        val description: String,
        val installedPackage: String? = null
    ) {
        val isInstalled: Boolean get() = installedPackage != null
    }

    data class HarvestReport(
        val outcome: HarvestOutcome,
        val configs: List<String>,
        val githubCount: Int,
        val telegramCount: Int,
        val usedMirror: Boolean,
        val activeVpnDetected: Boolean,
        val installedFallbackTools: List<FallbackTool>,
        val stepsLog: List<String>,
        val guidance: String,
        val downloadedFilesCount: Int = 0
    )

    /** Curated GitHub feeds with jsDelivr CDN mirrors when raw.githubusercontent.com is throttled. */
    val DEFAULT_GITHUB_FEEDS = listOf(
        FeedSource(
            name = "barry-far V2ray-Configs (VLESS)",
            primaryUrl = "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Splitted-By-Protocol/vless.txt",
            kind = SourceKind.GITHUB
        ),
        FeedSource(
            name = "Epodonios v2ray-configs (VLESS)",
            primaryUrl = "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/Epodonios/v2ray-configs@main/Splitted-By-Protocol/vless.txt",
            kind = SourceKind.GITHUB
        ),
        FeedSource(
            name = "MahsaNetConfigTopic (Sub)",
            primaryUrl = "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/main/xray_final.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/MahsaNetConfigTopic/config@main/xray_final.txt",
            kind = SourceKind.GITHUB
        ),
        FeedSource(
            name = "yebekhe Configs (VLESS)",
            primaryUrl = "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/yebekhe/TVC@main/subscriptions/xray/normal/vless",
            kind = SourceKind.GITHUB
        ),
        FeedSource(
            name = "barry-far V2ray-Configs (All Protocols)",
            primaryUrl = "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/All_Configs_Sub.txt",
            kind = SourceKind.GITHUB
        ),
        FeedSource(
            name = "Epodonios v2ray-configs (All Protocols)",
            primaryUrl = "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/Epodonios/v2ray-configs@main/All_Configs_Sub.txt",
            kind = SourceKind.GITHUB
        )
    )

    /** Dedicated chainable SOCKS5 / HTTP CONNECT proxy-list feeds (with jsDelivr CDN mirrors). */
    val DEFAULT_PROXY_CHAIN_FEEDS = listOf(
        FeedSource(
            name = "TheSpeedX SOCKS5",
            primaryUrl = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt",
            kind = SourceKind.GITHUB,
            defaultScheme = TunnelConfig.ProxyScheme.SOCKS5
        ),
        FeedSource(
            name = "TheSpeedX HTTP",
            primaryUrl = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/http.txt",
            kind = SourceKind.GITHUB,
            defaultScheme = TunnelConfig.ProxyScheme.HTTP
        ),
        FeedSource(
            name = "Monosans SOCKS5",
            primaryUrl = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt",
            kind = SourceKind.GITHUB,
            defaultScheme = TunnelConfig.ProxyScheme.SOCKS5
        ),
        FeedSource(
            name = "Monosans HTTP",
            primaryUrl = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/http.txt",
            kind = SourceKind.GITHUB,
            defaultScheme = TunnelConfig.ProxyScheme.HTTP
        ),
        FeedSource(
            name = "Proxifly SOCKS5",
            primaryUrl = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
            kind = SourceKind.GITHUB,
            defaultScheme = TunnelConfig.ProxyScheme.SOCKS5
        ),
        FeedSource(
            name = "Proxifly HTTP",
            primaryUrl = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
            kind = SourceKind.GITHUB,
            defaultScheme = TunnelConfig.ProxyScheme.HTTP
        ),
        FeedSource(
            name = "Hookzof SOCKS5",
            primaryUrl = "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/hookzof/socks5_list@master/proxy.txt",
            kind = SourceKind.GITHUB,
            defaultScheme = TunnelConfig.ProxyScheme.SOCKS5
        ),
        FeedSource(
            name = "Vakhov SOCKS5",
            primaryUrl = "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/vakhov/fresh-proxy-list@master/socks5.txt",
            kind = SourceKind.GITHUB,
            defaultScheme = TunnelConfig.ProxyScheme.SOCKS5
        ),
        FeedSource(
            name = "Vakhov HTTP",
            primaryUrl = "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/vakhov/fresh-proxy-list@master/http.txt",
            kind = SourceKind.GITHUB,
            defaultScheme = TunnelConfig.ProxyScheme.HTTP
        ),
        FeedSource(
            name = "KangProxy SOCKS5",
            primaryUrl = "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",
            mirrorUrl = "https://cdn.jsdelivr.net/gh/officialputuid/KangProxy@KangProxy/socks5/socks5.txt",
            kind = SourceKind.GITHUB,
            defaultScheme = TunnelConfig.ProxyScheme.SOCKS5
        )
    )

    val DEFAULT_PROXY_TELEGRAM_CHANNELS = listOf(
        "proxymtprotoir",
        "myseaproxy",
        "ShadowProxy66",
        "ConfigX2ray",
        "whitedns",
        "letsproxys1",
        "PrivateVPNs",
        "DirectVPN"
    )

    /** Public Telegram channels parsed via `https://t.me/s/<channel>`. */
    val DEFAULT_TELEGRAM_CHANNELS = listOf(
        "whitedns",
        "FarazV2ray",
        "ProxGp",
        "letsproxys1",
        "napsternetv",
        "AarazV2ray",
        "filembad",
        "v2ray1_ng",
        "proxymtprotoir",
        "ConfigX2ray",
        "ShadowProxy66",
        "V2ray_confiig",
        "daddynetwork",
        "AR14N24B",
        "cpy_teeL",
        "MARAMBASHI",
        "Zed_NetMeli",
        "purland",
        "myseaproxy",
        "v2rayngvpn",
        "Broz_time",
        "V2rayng_Fast",
        "meliproxyy",
        "Kamkarstore",
        "marambashi2",
        "KiaNet_GP",
        "ConfigWireguard",
        "AzadInternet_TV",
        "blackRay",
        "npvfree11",
        "chatnekonvaslshim",
        "ServerNettGap",
        "v2rayng_org",
        "PrivateVPNs",
        "DirectVPN",
        "vless_vmess",
        "v2ray_outlineir",
        "V2rayNGn",
        "outline_vpn",
        "v2ray_configs_pool",
        "VlessConfig",
        "FreeV2rays",
        "v2ray_saz",
        "meli_proxyy",
        "V2RayRoot",
        "ShadowSocks_s",
        "v2rayng_vpnrog",
        "iranproxy98",
        "Warp_ir",
        "v2ray_free_conf"
    )

    /** Curated circumvention & blackout rescue tools (including user-requested GitHub projects). */
    val KNOWN_FALLBACK_TOOLS = listOf(
        FallbackTool(
            name = "WhiteDNS Android",
            category = "DNS Blackout",
            packageNames = listOf("com.whitedns.app", "org.whitedns.android", "ir.whitedns.app"),
            githubUrl = "https://github.com/WhiteDNS/WhiteDNS-Android",
            description = "Clean DNS & blackout bypass client"
        ),
        FallbackTool(
            name = "WhiteVPN",
            category = "Blackout VPN",
            packageNames = listOf("com.whitevpn.app", "org.whitevpn.android"),
            githubUrl = "https://github.com/WhiteDNS/WhiteVPN",
            description = "Resilient VPN engineered for restricted networks"
        ),
        FallbackTool(
            name = "IP Range Scout",
            category = "Clean IP Scanner",
            packageNames = listOf("com.whitedns.iprangescout", "org.whitedns.ipscout"),
            githubUrl = "https://github.com/WhiteDNS/IP-Range-Scout-Android",
            description = "Scans clean CDN/DNS IPv4 ranges on Android"
        ),
        FallbackTool(
            name = "SlipNet",
            category = "DNS / Slipstream Tunnel",
            packageNames = listOf("com.anonvector.slipnet", "org.slipnet.app"),
            githubUrl = "https://github.com/anonvector/SlipNet",
            description = "DNS & stealth tunnel for extreme censorship"
        ),
        FallbackTool(
            name = "ShiroKhorshid Tools",
            category = "Anti-Censorship",
            packageNames = listOf("org.shirokhorshid.app"),
            githubUrl = "https://github.com/shirokhorshid",
            description = "Community circumvention configs & utilities"
        ),
        FallbackTool(
            name = "Lantern",
            category = "Fallback VPN",
            packageNames = listOf("org.getlantern.lantern"),
            githubUrl = "https://github.com/getlantern",
            description = "Multi-protocol censorship-resistant proxy"
        ),
        FallbackTool(
            name = "Tor / Orbot",
            category = "Onion Routing",
            packageNames = listOf("org.torproject.android", "org.torproject.torbrowser"),
            githubUrl = "https://github.com/thetorproject",
            description = "Tor network proxy & bridges for severe blocks"
        ),
        FallbackTool(
            name = "v2rayNG",
            category = "Xray Client",
            packageNames = listOf("com.v2ray.ang"),
            githubUrl = "https://github.com/2dust/v2rayNG",
            description = "Full VLESS / VMess / Trojan / Reality client"
        ),
        FallbackTool(
            name = "Hiddify",
            category = "Multi-Protocol VPN",
            packageNames = listOf("app.hiddify.com"),
            githubUrl = "https://github.com/hiddify/hiddify-app",
            description = "Sing-box multi-protocol client with auto-fragment"
        ),
        FallbackTool(
            name = "NekoBox",
            category = "Sing-Box Client",
            packageNames = listOf("moe.nb4a"),
            githubUrl = "https://github.com/MatsuriDayo/NekoBoxForAndroid",
            description = "Universal proxy toolchain for Android"
        ),
        FallbackTool(
            name = "Psiphon",
            category = "Fallback VPN",
            packageNames = listOf("com.psiphon3.subscription", "com.psiphon3"),
            githubUrl = "https://github.com/Psiphon-Labs",
            description = "SSH/Obfuscated fallback circumvention tool"
        ),
        FallbackTool(
            name = "Cloudflare WARP",
            category = "Edge Tunnel",
            packageNames = listOf("com.cloudflare.onedotonedotonedotone"),
            githubUrl = "https://1.1.1.1/",
            description = "1.1.1.1 DNS + WireGuard edge tunnel"
        ),
        FallbackTool(
            name = "WireGuard",
            category = "WireGuard Client",
            packageNames = listOf("com.wireguard.android"),
            githubUrl = "https://github.com/WireGuard/wireguard-android",
            description = "Official WireGuard .conf / wireguard:// VPN client"
        ),
        FallbackTool(
            name = "NapsternetV",
            category = "Multi-Protocol Client",
            packageNames = listOf("com.napsternetv.app", "com.napsternetv.vpn"),
            githubUrl = "https://t.me/napsternetv",
            description = "Supports .npvs, .npv4, npv://, Xray & WireGuard configs"
        ),
        FallbackTool(
            name = "OpenVPN for Android",
            category = "OpenVPN Client",
            packageNames = listOf("de.blinkt.openvpn"),
            githubUrl = "https://github.com/schwabe/ics-openvpn",
            description = "Open-source .ovpn / .openvpn client for TCP/UDP profiles"
        ),
        FallbackTool(
            name = "OpenVPN Connect",
            category = "OpenVPN Client",
            packageNames = listOf("net.openvpn.openvpn"),
            githubUrl = "https://openvpn.net/client/",
            description = "Official OpenVPN .ovpn / .openvpn client"
        ),
        FallbackTool(
            name = "HTTP Custom",
            category = "Custom Payload (.hc)",
            packageNames = listOf("xyz.easypro.httpcustom"),
            githubUrl = "https://t.me/s/ConfigX2ray",
            description = "Imports .hc SSH / V2Ray / UDP / SlowDNS config files"
        ),
        FallbackTool(
            name = "HTTP Injector",
            category = "Payload & SSH (.ehi/.custom)",
            packageNames = listOf("com.evozi.injector"),
            githubUrl = "https://t.me/s/letsproxys1",
            description = "Imports .ehi / .custom / .costum SSH & V2Ray tunnels"
        ),
        FallbackTool(
            name = "DarkTunnel",
            category = "Stealth Tunnel (.dark)",
            packageNames = listOf("net.darktunnel.app", "com.darktunnel.vpn"),
            githubUrl = "https://t.me/s/blackRay",
            description = "Imports .dark SSH, DNSTT & V2Ray tunnel files"
        ),
        FallbackTool(
            name = "TLS Tunnel",
            category = "TLS Tunnel (.tls)",
            packageNames = listOf("com.tlsvpn.tlstunnel"),
            githubUrl = "https://t.me/s/myseaproxy",
            description = "Imports .tls SNI/TLS encapsulated VPN profiles"
        ),
        FallbackTool(
            name = "HA Tunnel Plus",
            category = "Custom SNI (.hat)",
            packageNames = listOf("com.hatunnel.plus"),
            githubUrl = "https://t.me/s/ShadowProxy66",
            description = "Imports .hat custom header & payload profiles"
        ),
        FallbackTool(
            name = "NetMod",
            category = "Syna / NM (.nm)",
            packageNames = listOf("com.netmod.syna"),
            githubUrl = "https://t.me/s/ProxGp",
            description = "Imports .nm SSH / Xray / OpenVPN multi-protocol configs"
        )
    )

    /**
     * Pure-Kotlin universal extractor: decodes HTML entities, extracts all supported URI schemes
     * (VLESS/VMess/Trojan/SS/SSR/Hy2/TUIC/WireGuard/WARP/NapsternetV/MTProto/SOCKS/SSH/SlipNet),
     * parses WireGuard `[Interface]...[Peer]` INI blocks, and decodes nested Base64 blobs.
     */
    fun extractProxyConfigs(rawPayload: String, maxConfigs: Int = 4096): List<String> {
        return UniversalConfig.extractAll(rawPayload, maxConfigs)
    }

    fun protocolOf(uri: String): String = UniversalConfig.protocolOf(uri)

    /** Builds a GitHub raw URL -> jsDelivr mirror URL if possible. */
    fun toJsDelivrMirror(rawGithubUrl: String): String? {
        val prefix = "https://raw.githubusercontent.com/"
        if (!rawGithubUrl.startsWith(prefix, ignoreCase = true)) return null
        val rest = rawGithubUrl.substring(prefix.length)
        val parts = rest.split('/', limit = 4)
        if (parts.size < 4) return null
        val (owner, repo, branch, path) = parts
        return "https://cdn.jsdelivr.net/gh/$owner/$repo@$branch/$path"
    }

    /** Builds a GitHub raw URL -> Statically CDN mirror URL if possible. */
    fun toStaticallyMirror(rawGithubUrl: String): String? {
        val prefix = "https://raw.githubusercontent.com/"
        if (!rawGithubUrl.startsWith(prefix, ignoreCase = true)) return null
        val rest = rawGithubUrl.substring(prefix.length)
        val parts = rest.split('/', limit = 4)
        if (parts.size < 4) return null
        val (owner, repo, branch, path) = parts
        return "https://cdn.statically.io/gh/$owner/$repo/$branch/$path"
    }

    /** Returns ordered fallback URLs for any feed (`raw` -> `cdn.jsdelivr.net` -> `cdn.statically.io`). */
    fun toMirrorUrls(url: String): List<String> {
        val raw = HarvestSourceStore.normalizeGithubUrl(url) ?: return emptyList()
        val out = LinkedHashSet<String>()
        out.add(raw)
        toJsDelivrMirror(raw)?.let { out.add(it) }
        toStaticallyMirror(raw)?.let { out.add(it) }
        return out.toList()
    }

    /** Extracts the smallest numeric message ID from `data-post="<channel>/<id>"` tags in a `t.me/s/<channel>` HTML page. */
    fun extractMinTelegramPostId(html: String, channel: String): Long? {
        val escaped = Regex.escape(channel.trim().removePrefix("@"))
        val postRegex = Regex("""data-post=["']$escaped/(\d+)["']""", RegexOption.IGNORE_CASE)
        var minId: Long? = null
        for (m in postRegex.findAll(html)) {
            val id = m.groupValues[1].toLongOrNull() ?: continue
            if (minId == null || id < minId) {
                minId = id
            }
        }
        return minId
    }

    /** Scrapes up to [maxPages] recent pages of a public Telegram channel (`t.me/s/<channel>?before=<id>`). */
    fun fetchTelegramChannelPages(
        channel: String,
        maxPages: Int = 3,
        timeoutMs: Int = 4500
    ): List<String> {
        val clean = HarvestSourceStore.normalizeTelegramChannel(channel) ?: return emptyList()
        val pages = ArrayList<String>()
        var cursor: Long? = null
        val total = maxPages.coerceIn(1, 5)
        for (pageIdx in 0 until total) {
            val url = if (cursor == null) {
                "https://t.me/s/$clean"
            } else {
                "https://t.me/s/$clean?before=$cursor"
            }
            val html = httpGet(url, timeoutMs) ?: break
            if (html.isBlank()) break
            pages.add(html)
            val minId = extractMinTelegramPostId(html, clean) ?: break
            if (cursor != null && minId >= cursor) break
            if (minId <= 1L) break
            cursor = minId
        }
        return pages
    }

    /** Fetches a single Telegram post (`https://t.me/<channel>/<id>?embed=1`, falling back to `/s/<channel>/<id>`). */
    fun fetchTelegramPostBody(postUrl: String, timeoutMs: Int = 4500): String? {
        val norm = HarvestSourceStore.normalizeTelegramPost(postUrl) ?: return null
        val embedBody = httpGet("$norm?embed=1", timeoutMs)
        if (!embedBody.isNullOrBlank()) return embedBody
        val slug = norm.substringAfter("t.me/")
        return httpGet("https://t.me/s/$slug", timeoutMs)
    }

    /** Returns true when [uri] belongs to the requested protocol [filter] (case-insensitive, alias-aware). */
    fun matchesProtocolFilter(uri: String, filter: String): Boolean {
        val cleanFilter = filter.trim().lowercase()
        if (cleanFilter.isEmpty() || cleanFilter == "all") return true
        val proto = UniversalConfig.canonicalProtocol(protocolOf(uri))
        if (cleanFilter == "http/https" || cleanFilter == "http_https") {
            return proto == "http" || proto == "https"
        }
        return proto == UniversalConfig.canonicalProtocol(cleanFilter)
    }

    /** Filters and deduplicates [configs] by canonical protocol and `protocol+host+port+id`. */
    fun filterByProtocol(configs: Collection<String>, protocolFilter: String): List<String> {
        return UniversalConfig.deduplicate(configs).filter { matchesProtocolFilter(it, protocolFilter) }
    }

    /** Detects which fallback circumvention apps are installed on this Android device. */
    fun detectFallbackTools(context: Context): List<FallbackTool> {
        val pm = context.packageManager
        return KNOWN_FALLBACK_TOOLS.map { tool ->
            val installed = tool.packageNames.firstOrNull { pkg -> isPackageInstalled(pm, pkg) }
            tool.copy(installedPackage = installed)
        }
    }

    /** Checks if ANY VPN (DastYab or another app like Lantern/Orbot/WhiteVPN/v2rayNG) is currently active. */
    fun isAnyVpnActive(context: Context): Boolean {
        if (DastyabVpnService.isConnected()) return true
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val active = cm.activeNetwork ?: return false
                val caps = cm.getNetworkCapabilities(active) ?: return false
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Runs the full resilient multi-stage harvest:
     *  1. Try GitHub raw feeds first (+ jsDelivr mirror fallback if raw GitHub is blocked).
     *  2. Try Telegram public channels (`t.me/s/<channel>`).
     *  3. If both fail, inspect active VPNs & installed fallback tools, and return actionable
     *     guidance (Alternate VPN → Bootstrap Temporary Config → Emergency DNS Blackout VPN).
     */
    fun harvestResilient(
        context: Context,
        customGithubUrls: List<String> = emptyList(),
        customTelegramChannels: List<String> = emptyList(),
        onProgress: (String) -> Unit = {}
    ): HarvestReport {
        val log = mutableListOf<String>()
        fun logStep(msg: String) {
            log.add(msg)
            onProgress(msg)
        }

        val activeVpn = isAnyVpnActive(context)
        val fallbackTools = detectFallbackTools(context)
        val installedTools = fallbackTools.filter { it.isInstalled }
        logStep("Network check: activeVpn=$activeVpn, fallbackAppsInstalled=${installedTools.size}")

        val allConfigs = LinkedHashSet<String>()
        var githubCount = 0
        var telegramCount = 0
        var downloadedFilesCount = 0
        var usedMirror = false

        // ── STAGE 1: GitHub Direct + jsDelivr Mirror Fallback ──
        val effectiveGithubUrls = (customGithubUrls + HarvestSourceStore.getCustomGithubUrls(context))
            .mapNotNull { HarvestSourceStore.normalizeGithubUrl(it) }
            .distinct()
        logStep("Stage 1/4: Trying GitHub config feeds first (${effectiveGithubUrls.size} custom + ${DEFAULT_GITHUB_FEEDS.size} built-in)…")
        val githubFeeds = buildList {
            effectiveGithubUrls.forEachIndexed { idx, url ->
                add(FeedSource("Custom GitHub #${idx + 1}", url, toJsDelivrMirror(url), SourceKind.GITHUB))
            }
            addAll(DEFAULT_GITHUB_FEEDS)
        }

        for (feed in githubFeeds) {
            val body = httpGet(feed.primaryUrl, timeoutMs = 5500)
            if (body != null) {
                val (files, fileUris) = ConfigFileHarvester.harvestFilesFromBody(context, body, feed.name, maxDownloadsPerSource = 8)
                downloadedFilesCount += files.count { it.isDownloadedLocally }
                val extracted = (extractProxyConfigs(body, maxConfigs = 4096) + fileUris).distinct()
                if (extracted.isNotEmpty() || files.isNotEmpty()) {
                    allConfigs.addAll(extracted)
                    githubCount += extracted.size
                    logStep("  ✓ GitHub direct [${feed.name}]: +${extracted.size} configs, ${files.size} files")
                    continue
                }
            }
            // Fallback to jsDelivr mirror if GitHub raw was blocked/timed out
            val mirror = feed.mirrorUrl
            if (mirror != null) {
                val mirrorBody = httpGet(mirror, timeoutMs = 5500)
                if (mirrorBody != null) {
                    val (files, fileUris) = ConfigFileHarvester.harvestFilesFromBody(context, mirrorBody, feed.name, maxDownloadsPerSource = 8)
                    downloadedFilesCount += files.count { it.isDownloadedLocally }
                    val extracted = (extractProxyConfigs(mirrorBody, maxConfigs = 4096) + fileUris).distinct()
                    if (extracted.isNotEmpty() || files.isNotEmpty()) {
                        usedMirror = true
                        allConfigs.addAll(extracted)
                        githubCount += extracted.size
                        logStep("  ✓ GitHub mirror (jsDelivr) [${feed.name}]: +${extracted.size} configs, ${files.size} files")
                        continue
                    }
                }
            }
            logStep("  ✗ Unreachable: ${feed.name}")
        }

        // ── STAGE 2: Telegram Public Channels (Concurrent Multi-Channel Harvest) ──
        val customChannels = HarvestSourceStore.getCustomTelegramChannels(context)
        val channels = (customTelegramChannels + customChannels + DEFAULT_TELEGRAM_CHANNELS)
            .mapNotNull { HarvestSourceStore.normalizeTelegramChannel(it) }
            .distinctBy { it.lowercase() }
        logStep("Stage 2/4: Checking ${channels.size} Telegram channels (${customChannels.size} custom + ${DEFAULT_TELEGRAM_CHANNELS.size} built-in) concurrently…")

        val tgPool = Executors.newFixedThreadPool(8)
        try {
            val tasks = channels.map { channel ->
                Callable {
                    val body = httpGet("https://t.me/s/$channel", timeoutMs = 4500)
                    if (body == null) {
                        Triple(channel, emptyList<String>(), 0)
                    } else {
                        val (files, fileUris) = ConfigFileHarvester.harvestFilesFromBody(
                            context = context,
                            rawBody = body,
                            sourceLabel = "@$channel",
                            maxDownloadsPerSource = 6
                        )
                        val extracted = (extractProxyConfigs(body, maxConfigs = 4096) + fileUris).distinct()
                        Triple(channel, extracted, files.size)
                    }
                }
            }
            val futures = tgPool.invokeAll(tasks, 20, TimeUnit.SECONDS)
            for (future in futures) {
                val (channel, extracted, fileCount) = runCatching { future.get() }.getOrNull() ?: continue
                if (extracted.isNotEmpty() || fileCount > 0) {
                    allConfigs.addAll(extracted)
                    telegramCount += extracted.size
                    downloadedFilesCount += fileCount
                    val fileNote = if (fileCount > 0) ", $fileCount files" else ""
                    logStep("  ✓ Telegram @$channel: +${extracted.size} configs$fileNote")
                }
            }
        } finally {
            tgPool.shutdownNow()
        }
        if (telegramCount == 0 && downloadedFilesCount == 0) {
            logStep("  ✗ All ${channels.size} Telegram channels were unreachable.")
        }

        val finalList = UniversalConfig.mergeBalanced(allConfigs, limit = 4096)

        // Also harvest/preserve chainable SOCKS5/HTTP hops separately so VLESS lists never crowd them out
        val chainHopsFromMain = UniversalConfig.extractChainableProxyHops(allConfigs)
        if (chainHopsFromMain.isNotEmpty()) {
            val mergedPool = (chainHopsFromMain + TunnelConfig.loadHarvestedProxyHops(context))
                .distinctBy { "${it.scheme.name}:${it.host}:${it.port}" }
            TunnelConfig.saveHarvestedProxyHops(context, mergedPool)
        }

        if (finalList.isNotEmpty() || downloadedFilesCount > 0) {
            if (finalList.isNotEmpty()) {
                TunnelConfig.saveHarvestedConfigs(context, finalList)
            }
            val outcome = when {
                githubCount > 0 && (telegramCount > 0 || downloadedFilesCount > 0) -> HarvestOutcome.SUCCESS_MIXED
                githubCount > 0 -> HarvestOutcome.SUCCESS_GITHUB
                else -> HarvestOutcome.SUCCESS_TELEGRAM
            }
            val msg = "Harvested ${finalList.size} configs & $downloadedFilesCount files (GitHub: $githubCount, Telegram: $telegramCount). Saved offline."
            logStep("OK: $msg")
            return HarvestReport(
                outcome = outcome,
                configs = finalList,
                githubCount = githubCount,
                telegramCount = telegramCount,
                usedMirror = usedMirror,
                activeVpnDetected = activeVpn,
                installedFallbackTools = installedTools,
                stepsLog = log,
                guidance = msg,
                downloadedFilesCount = downloadedFilesCount
            )
        }

        // ── STAGE 3 & 4: Both GitHub & Telegram unreachable ──
        logStep("Stage 3/4: GitHub & Telegram unreachable. Checking alternate VPNs & bootstrap options…")
        val savedBootstrap = TunnelConfig.load(context).bootstrapConfig
        if (savedBootstrap.isNotBlank() && !activeVpn) {
            logStep("  ℹ Temporary bootstrap config is saved — connect with it first, then re-harvest.")
        }

        return when {
            installedTools.isNotEmpty() && !activeVpn -> {
                val names = installedTools.joinToString(", ") { it.name }
                val guide = "GitHub and Telegram are blocked on this connection. " +
                    "Detected fallback VPN(s): $names. " +
                    "Tap any installed fallback VPN below to connect temporarily, then tap Harvest Again — " +
                    "OR paste a temporary base working config into DastYab, OR activate Emergency DNS Blackout VPN."
                logStep("Stage 4/4: Fallback VPNs available ($names).")
                HarvestReport(
                    outcome = HarvestOutcome.NEEDS_ALTERNATE_VPN,
                    configs = TunnelConfig.loadHarvestedConfigs(context),
                    githubCount = 0,
                    telegramCount = 0,
                    usedMirror = false,
                    activeVpnDetected = false,
                    installedFallbackTools = installedTools,
                    stepsLog = log,
                    guidance = guide
                )
            }
            !activeVpn -> {
                val guide = "No direct access to GitHub or Telegram and no fallback VPN is active. " +
                    "Two recovery options:\n" +
                    "1) Tap 'Set Temporary Base Config' to paste any single working vless:// / vmess:// / trojan:// link, connect DastYab VPN, and then re-harvest free configs automatically.\n" +
                    "2) Under total blackout, activate 'Emergency DNS Blackout VPN' (WhiteDNS / DoH / SlipNet) and run 'Clean IP & DNS Scout'."
                logStep("Stage 4/4: Requesting Temporary Base Config or Emergency DNS Blackout VPN.")
                HarvestReport(
                    outcome = HarvestOutcome.NEEDS_BOOTSTRAP_CONFIG,
                    configs = TunnelConfig.loadHarvestedConfigs(context),
                    githubCount = 0,
                    telegramCount = 0,
                    usedMirror = false,
                    activeVpnDetected = false,
                    installedFallbackTools = installedTools,
                    stepsLog = log,
                    guidance = guide
                )
            }
            else -> {
                val guide = "Even with an active VPN, GitHub & Telegram timed out (severe blackout / DNS poisoning). " +
                    "Switch to 'Emergency DNS Blackout VPN' (DoH / WhiteDNS), run 'Clean IP & DNS Scout' to find a clean edge IP, " +
                    "or replace your temporary base config with a fresh working link."
                logStep("Stage 4/4: Severe blackout detected — recommending DNS Blackout VPN + IP Scout.")
                HarvestReport(
                    outcome = HarvestOutcome.BLACKOUT_DNS_ONLY,
                    configs = TunnelConfig.loadHarvestedConfigs(context),
                    githubCount = 0,
                    telegramCount = 0,
                    usedMirror = false,
                    activeVpnDetected = true,
                    installedFallbackTools = installedTools,
                    stepsLog = log,
                    guidance = guide
                )
            }
        }
    }

    /**
     * Concurrently harvests diverse chainable SOCKS5 / HTTP CONNECT hops across GitHub proxy-list
     * repos, jsDelivr CDN mirrors, custom user sources, and Telegram channels, preserving
     * per-`/16` subnet spread and saving the updated pool offline in [TunnelConfig].
     */
    fun harvestProxyChainPool(
        context: Context,
        maxHops: Int = 240,
        excludedHosts: Set<String> = emptySet(),
        excludedSubnets16: Set<String> = emptySet(),
        onProgress: (String) -> Unit = {}
    ): List<TunnelConfig.ProxyHop> {
        val collected = LinkedHashMap<String, TunnelConfig.ProxyHop>()
        val customGithub = HarvestSourceStore.getCustomGithubUrls(context)
            .mapNotNull { HarvestSourceStore.normalizeGithubUrl(it) }
            .mapIndexed { idx, url ->
                val defaultScheme = if (url.contains("http", ignoreCase = true) && !url.contains("socks", ignoreCase = true)) {
                    TunnelConfig.ProxyScheme.HTTP
                } else {
                    TunnelConfig.ProxyScheme.SOCKS5
                }
                FeedSource("Custom Proxy #${idx + 1}", url, toJsDelivrMirror(url), SourceKind.GITHUB, defaultScheme)
            }

        val feeds = customGithub + DEFAULT_PROXY_CHAIN_FEEDS
        onProgress("Fetching fresh SOCKS5/HTTP proxy pools (${feeds.size} feeds + ${DEFAULT_PROXY_TELEGRAM_CHANNELS.size} Telegram)…")

        val pool = Executors.newFixedThreadPool(6)
        try {
            val feedTasks = feeds.map { feed ->
                Callable {
                    var body = httpGet(feed.primaryUrl, timeoutMs = 4200)
                    var hops = if (body != null) {
                        UniversalConfig.extractProxyListHops(body, feed.defaultScheme, maxHops = 60)
                    } else {
                        emptyList()
                    }
                    if (hops.isEmpty() && feed.mirrorUrl != null) {
                        body = httpGet(feed.mirrorUrl, timeoutMs = 4200)
                        if (body != null) {
                            hops = UniversalConfig.extractProxyListHops(body, feed.defaultScheme, maxHops = 60)
                        }
                    }
                    feed.name to hops
                }
            }
            val tgChannels = (HarvestSourceStore.getCustomTelegramChannels(context) + DEFAULT_PROXY_TELEGRAM_CHANNELS)
                .mapNotNull { HarvestSourceStore.normalizeTelegramChannel(it) }
                .distinctBy { it.lowercase() }
                .take(12)
            val tgTasks = tgChannels.map { channel ->
                Callable {
                    val body = httpGet("https://t.me/s/$channel", timeoutMs = 3800)
                    val hops = if (body != null) {
                        UniversalConfig.extractProxyListHops(body, TunnelConfig.ProxyScheme.DIRECT, maxHops = 40)
                    } else {
                        emptyList()
                    }
                    "@$channel" to hops
                }
            }

            val allFutures = pool.invokeAll(feedTasks + tgTasks, 15, TimeUnit.SECONDS)
            for (future in allFutures) {
                val (label, hops) = runCatching { future.get() }.getOrNull() ?: continue
                if (hops.isNotEmpty()) {
                    var added = 0
                    for (h in hops) {
                        val key = "${h.scheme.name}:${h.host}:${h.port}"
                        if (collected.putIfAbsent(key, h) == null) added++
                    }
                    if (added > 0) {
                        onProgress("  ✓ Proxy feed [$label]: +$added hops")
                    }
                }
            }
        } catch (_: Exception) {
        } finally {
            pool.shutdownNow()
        }

        // Fallback/supplement with existing stored pool & harvested URIs
        val existingPool = TunnelConfig.loadChainableProxyPool(context)
        val combined = LinkedHashMap<String, TunnelConfig.ProxyHop>(collected)
        for (h in existingPool) {
            combined.putIfAbsent("${h.scheme.name}:${h.host}:${h.port}", h)
        }

        val diverse = UniversalConfig.selectDiverseProxyHops(
            hops = combined.values.toList(),
            limit = maxHops.coerceAtLeast(16),
            excludedHosts = excludedHosts,
            excludedSubnets16 = excludedSubnets16
        )
        if (diverse.isNotEmpty()) {
            TunnelConfig.saveHarvestedProxyHops(context, diverse)
        }
        return diverse
    }

    data class UnifiedHarvestResult(
        val configs: List<String>,
        val sourcesAttempted: Int,
        val sourcesSucceeded: Int,
        val usedMirror: Boolean,
        val downloadedFilesCount: Int,
        val log: List<String>
    )

    /**
     * Concurrently harvests all enabled sources from [HarvestSourceStore.getAllSources]
     * (`GITHUB_RAW` with 3-mirror fallback, `SUBSCRIPTION_URL`, `TELEGRAM_CHANNEL` multi-page
     * scraping via `?before=`, and `TELEGRAM_POST` single-post embeds), updates per-source stats,
     * deduplicates by `protocol+host+port+id`, applies optional [protocolFilter], and saves offline.
     */
    fun harvestFromUnifiedSources(
        context: Context,
        protocolFilter: String = "all",
        telegramPages: Int = 3,
        maxConcurrency: Int = 8,
        onProgress: (String) -> Unit = {}
    ): UnifiedHarvestResult {
        val sources = HarvestSourceStore.getAllSources(context).filter { it.enabled }
        val log = ArrayList<String>()
        fun step(msg: String) {
            log.add(msg)
            onProgress(msg)
        }
        if (sources.isEmpty()) {
            step("No enabled sources in Source Manager.")
            return UnifiedHarvestResult(emptyList(), 0, 0, false, 0, log)
        }

        step("Harvesting ${sources.size} enabled sources (filter=${protocolFilter.ifBlank { "all" }})…")
        data class SingleSourceOutcome(
            val source: HarvestSourceStore.HarvestSource,
            val uris: List<String>,
            val fileCount: Int,
            val success: Boolean,
            val usedMirror: Boolean,
            val note: String
        )

        val allUris = LinkedHashSet<String>()
        var succeeded = 0
        var usedMirror = false
        var totalFiles = 0

        val pool = Executors.newFixedThreadPool(maxConcurrency.coerceIn(2, 12))
        try {
            val tasks = sources.map { src ->
                Callable {
                    when (src.type) {
                        HarvestSourceStore.SourceType.GITHUB_RAW,
                        HarvestSourceStore.SourceType.SUBSCRIPTION_URL -> {
                            val candidates = toMirrorUrls(src.value)
                            var extracted = emptyList<String>()
                            var filesFound = 0
                            var ok = false
                            var mirrored = false
                            for ((idx, candidateUrl) in candidates.withIndex()) {
                                val body = httpGet(candidateUrl, timeoutMs = 5500) ?: continue
                                val (files, fileUris) = ConfigFileHarvester.harvestFilesFromBody(
                                    context,
                                    body,
                                    src.name,
                                    maxDownloadsPerSource = 6
                                )
                                filesFound += files.count { it.isDownloadedLocally }
                                extracted = (extractProxyConfigs(body, maxConfigs = 4096) + fileUris).distinct()
                                if (extracted.isNotEmpty() || files.isNotEmpty()) {
                                    ok = true
                                    mirrored = idx > 0
                                    break
                                }
                            }
                            val via = if (mirrored) " (CDN mirror)" else ""
                            val note = if (ok) "✓ ${src.name}$via: +${extracted.size}" else "✗ ${src.name}"
                            SingleSourceOutcome(src, extracted, filesFound, ok, mirrored, note)
                        }
                        HarvestSourceStore.SourceType.TELEGRAM_CHANNEL -> {
                            val pages = fetchTelegramChannelPages(src.value, maxPages = telegramPages, timeoutMs = 4500)
                            if (pages.isEmpty()) {
                                SingleSourceOutcome(src, emptyList(), 0, false, false, "✗ @${src.value}")
                            } else {
                                val found = LinkedHashSet<String>()
                                var filesFound = 0
                                pages.forEachIndexed { pageIdx, pageHtml ->
                                    if (pageIdx == 0) {
                                        val (files, fileUris) = ConfigFileHarvester.harvestFilesFromBody(
                                            context = context,
                                            rawBody = pageHtml,
                                            sourceLabel = "@${src.value}",
                                            maxDownloadsPerSource = 6
                                        )
                                        filesFound += files.count { it.isDownloadedLocally }
                                        found.addAll(fileUris)
                                    }
                                    found.addAll(extractProxyConfigs(pageHtml, maxConfigs = 4096))
                                }
                                val list = found.toList()
                                val ok = list.isNotEmpty() || filesFound > 0
                                val note = if (ok) {
                                    "✓ @${src.value} (${pages.size}p): +${list.size}"
                                } else {
                                    "✗ @${src.value} (0 configs)"
                                }
                                SingleSourceOutcome(src, list, filesFound, ok, false, note)
                            }
                        }
                        HarvestSourceStore.SourceType.TELEGRAM_POST -> {
                            val body = fetchTelegramPostBody(src.value, timeoutMs = 4500)
                            if (body.isNullOrBlank()) {
                                SingleSourceOutcome(src, emptyList(), 0, false, false, "✗ ${src.name}")
                            } else {
                                val (files, fileUris) = ConfigFileHarvester.harvestFilesFromBody(
                                    context = context,
                                    rawBody = body,
                                    sourceLabel = src.name,
                                    maxDownloadsPerSource = 6
                                )
                                val filesFound = files.count { it.isDownloadedLocally }
                                val list = (extractProxyConfigs(body, maxConfigs = 4096) + fileUris).distinct()
                                val ok = list.isNotEmpty() || filesFound > 0
                                val note = if (ok) "✓ ${src.name}: +${list.size}" else "✗ ${src.name} (0 configs)"
                                SingleSourceOutcome(src, list, filesFound, ok, false, note)
                            }
                        }
                    }
                }
            }
            val futures = pool.invokeAll(tasks, 35, TimeUnit.SECONDS)
            for (future in futures) {
                val res = runCatching { future.get() }.getOrNull() ?: continue
                HarvestSourceStore.recordFetchResult(context, res.source.id, res.uris.size, res.success)
                if (res.success) {
                    succeeded++
                    allUris.addAll(res.uris)
                }
                if (res.usedMirror) usedMirror = true
                totalFiles += res.fileCount
                step("  ${res.note}")
            }
        } catch (_: Exception) {
        } finally {
            pool.shutdownNow()
        }

        val filtered = filterByProtocol(allUris, protocolFilter)
        val merged = UniversalConfig.mergeBalanced(filtered, limit = 4096)
        if (merged.isNotEmpty()) {
            TunnelConfig.saveHarvestedConfigs(context, merged)
        }
        val hops = UniversalConfig.extractChainableProxyHops(allUris)
        if (hops.isNotEmpty()) {
            val combinedHops = (hops + TunnelConfig.loadHarvestedProxyHops(context))
                .distinctBy { "${it.scheme.name}:${it.host}:${it.port}" }
            TunnelConfig.saveHarvestedProxyHops(context, combinedHops)
        }
        step("Done: ${merged.size} unique configs ($succeeded/${sources.size} sources OK).")
        return UnifiedHarvestResult(
            configs = merged,
            sourcesAttempted = sources.size,
            sourcesSucceeded = succeeded,
            usedMirror = usedMirror,
            downloadedFilesCount = totalFiles,
            log = log
        )
    }

    /**
     * Benchmarks [configs] concurrently with TLS/SNI + TCP probes, sorts fastest-first,
     * and keeps only reachable endpoints by default.
     */
    fun testAndRankConfigs(
        configs: List<String>,
        maxToTest: Int = 45,
        timeoutMs: Int = 2000,
        keepOnlyReachable: Boolean = true
    ): List<HarvestSourceStore.ConfigProbeResult> {
        val ranked = HarvestSourceStore.benchmarkHarvestedConfigs(
            configs = configs,
            maxToTest = maxToTest,
            timeoutMs = timeoutMs,
            verifyTls = true
        )
        return if (keepOnlyReachable) ranked.filter { it.reachable } else ranked
    }

    const val CLIENT_PACKAGE_V2RAYNG = "com.v2ray.ang"
    const val CLIENT_PACKAGE_HIDDIFY = "app.hiddify.com"
    const val CLIENT_PACKAGE_NEKOBOX = "moe.nb4a"

    /** Renders newline-separated share URIs for clipboard copy, text export, or v2rayNG import. */
    fun toPlainTextExport(configs: Collection<String>): String {
        return configs.map { it.trim() }.filter { it.isNotEmpty() }.joinToString("\n")
    }

    /** Renders standard Base64 subscription payload (pure Kotlin, no Android runtime dependency). */
    fun toBase64Subscription(configs: Collection<String>): String {
        val plain = toPlainTextExport(configs)
        if (plain.isEmpty()) return ""
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val bytes = plain.toByteArray(Charsets.UTF_8)
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

    /**
     * Copies exported configs to the clipboard and shares directly to [packageName] (v2rayNG /
     * Hiddify / NekoBox) via Android Share Sheet / direct package intent.
     */
    fun shareToExternalClient(
        context: Context,
        packageName: String,
        clientLabel: String,
        configs: Collection<String>
    ): Boolean {
        val payload = toPlainTextExport(configs)
        if (payload.isEmpty()) return false
        UiSafety.copyTextSafely(context, "DastYab $clientLabel Export", payload)

        val installed = isPackageInstalled(context.packageManager, packageName)
        if (installed) {
            val targetedSend = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, payload)
                setPackage(packageName)
            }
            if (UiSafety.safeStartActivity(context, targetedSend)) return true
            val launchIntent = context.packageManager.getLaunchIntentForPackage(packageName)
            if (launchIntent != null && UiSafety.safeStartActivity(context, launchIntent)) {
                Toast.makeText(
                    context,
                    context.getString(R.string.source_mgr_copied_for_client, clientLabel),
                    Toast.LENGTH_LONG
                ).show()
                return true
            }
        }
        val chooser = Intent.createChooser(
            Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, payload)
            },
            clientLabel
        )
        return UiSafety.safeStartActivity(context, chooser)
    }

    private fun httpGet(urlStr: String, timeoutMs: Int): String? {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                instanceFollowRedirects = true
                setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) DastYab/1.7")
                setRequestProperty("Accept", "text/plain, text/html, */*")
            }
            val code = conn.responseCode
            if (code !in 200..299) return null
            BufferedReader(InputStreamReader(conn.inputStream, Charsets.UTF_8)).use { reader ->
                val sb = StringBuilder()
                val buf = CharArray(4096)
                var total = 0
                while (total < 4_000_000) {
                    val n = reader.read(buf)
                    if (n < 0) break
                    sb.append(buf, 0, n)
                    total += n
                }
                sb.toString()
            }
        } catch (_: Exception) {
            null
        } finally {
            conn?.disconnect()
        }
    }

    private fun isPackageInstalled(pm: PackageManager, pkg: String): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= 33) {
                pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, 0)
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun priorityRank(uri: String): Int = UniversalConfig.priorityRank(uri)
}
