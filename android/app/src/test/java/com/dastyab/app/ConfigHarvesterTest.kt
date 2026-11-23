package com.dastyab.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hermetic JVM unit tests for [ConfigHarvester] URI extraction, HTML unescaping,
 * jsDelivr mirror conversion, and protocol prioritization.
 */
class ConfigHarvesterTest {

    @Test
    fun extractProxyConfigs_handlesTelegramHtmlAndPrioritizesVless() {
        val html = """
            <div class="tgme_widget_message_text">
                trojan://secretpass@tr.example.com:443?sni=tr.example.com#TrojanNode<br/>
                vless://11111111-2222-3333-4444-555555555555@edge.example.com:443?security=tls&amp;type=ws&amp;sni=cdn.example.com#VlessNode
            </div>
        """.trimIndent()

        val configs = ConfigHarvester.extractProxyConfigs(html)
        assertEquals(2, configs.size)
        assertTrue("VLESS should be prioritized first", configs[0].startsWith("vless://"))
        assertTrue("HTML &amp; should be unescaped", configs[0].contains("&type=ws&sni=cdn.example.com"))
        assertTrue(configs[1].startsWith("trojan://"))
    }

    @Test
    fun toJsDelivrMirror_convertsRawGithubUrls() {
        val raw = "https://raw.githubusercontent.com/WhiteDNS/WhiteVPN/main/configs/vless.txt"
        assertEquals(
            "https://cdn.jsdelivr.net/gh/WhiteDNS/WhiteVPN@main/configs/vless.txt",
            ConfigHarvester.toJsDelivrMirror(raw)
        )
        assertNull(ConfigHarvester.toJsDelivrMirror("https://example.com/list.txt"))
    }

    @Test
    fun knownFallbackTools_includesRequestedAntiCensorshipProjects() {
        val urls = ConfigHarvester.KNOWN_FALLBACK_TOOLS.map { it.githubUrl }
        assertTrue(urls.contains("https://github.com/WhiteDNS/WhiteDNS-Android"))
        assertTrue(urls.contains("https://github.com/WhiteDNS/WhiteVPN"))
        assertTrue(urls.contains("https://github.com/WhiteDNS/IP-Range-Scout-Android"))
        assertTrue(urls.contains("https://github.com/anonvector/SlipNet"))
        assertTrue(urls.contains("https://github.com/shirokhorshid"))
        assertTrue(urls.contains("https://github.com/getlantern"))
        assertTrue(urls.contains("https://github.com/thetorproject"))
    }

    @Test
    fun defaultTelegramChannels_includesWhiteDnsAndAllRequestedChannels() {
        val expected = listOf(
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
            "ServerNettGap"
        )
        val channels = ConfigHarvester.DEFAULT_TELEGRAM_CHANNELS
        expected.forEach { ch ->
            assertTrue("Missing channel $ch", channels.contains(ch))
        }
        assertEquals("DEFAULT_TELEGRAM_CHANNELS must not have duplicate handles", channels.distinct().size, channels.size)
    }

    @Test
    fun extractProxyConfigs_extractsWireGuardIniNapsternetVAndMtproto() {
        val html = """
            <div class="tgme_widget_message_text">
                [Interface]<br/>
                PrivateKey = priv12345=<br/>
                [Peer]<br/>
                PublicKey = pub12345=<br/>
                Endpoint = 162.159.192.1:2408<br/>
                npv4://user@npv.example.com:443#NpvFast<br/>
                tg://proxy?server=1.2.3.4&amp;port=443&amp;secret=dd000011<br/>
                vless://11111111-2222-3333-4444-555555555555@edge.example.com:443#VlessEdge
            </div>
        """.trimIndent()
        val configs = ConfigHarvester.extractProxyConfigs(html)
        assertTrue(configs.any { it.startsWith("vless://") })
        assertTrue(configs.any { it.startsWith("wireguard://") })
        assertTrue(configs.any { it.startsWith("npv4://") })
        assertTrue(configs.any { it == "tg://proxy?server=1.2.3.4&port=443&secret=dd000011" })

        val ovpnConfigs = ConfigHarvester.extractProxyConfigs("client\ndev tun\nproto udp\nremote 91.2.3.4 1194")
        assertTrue(ovpnConfigs.any { it.startsWith("openvpn://91.2.3.4:1194") })
    }

    @Test
    fun knownFallbackTools_coversOpenVpnWireGuardNapsternetAndTunnelFileClients() {
        val names = ConfigHarvester.KNOWN_FALLBACK_TOOLS.map { it.name }.toSet()
        assertTrue("OpenVPN for Android" in names)
        assertTrue("OpenVPN Connect" in names)
        assertTrue("HTTP Custom" in names)
        assertTrue("HTTP Injector" in names)
        assertTrue("DarkTunnel" in names)
        assertTrue("TLS Tunnel" in names)
        assertTrue("HA Tunnel Plus" in names)
        assertTrue("NetMod" in names)
        assertTrue("WireGuard" in names)
        assertTrue("NapsternetV" in names)
    }

    @Test
    fun mirrorUrlsAndTelegramPagination_extractCursorsAndMirrorsCorrectly() {
        val raw = "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt"
        val mirrors = ConfigHarvester.toMirrorUrls(raw)
        assertEquals(3, mirrors.size)
        assertEquals(raw, mirrors[0])
        assertEquals("https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/All_Configs_Sub.txt", mirrors[1])
        assertEquals("https://cdn.statically.io/gh/barry-far/V2ray-Configs/main/All_Configs_Sub.txt", mirrors[2])

        val html = """
            <div data-post="whitedns/5120">msg1</div>
            <div data-post="whitedns/5112">msg2</div>
            <div data-post="otherchan/100">ignore</div>
        """.trimIndent()
        assertEquals(5112L, ConfigHarvester.extractMinTelegramPostId(html, "whitedns"))
    }

    @Test
    fun filterByProtocol_andBase64Export_deduplicatesAndFiltersCleanly() {
        val raw = listOf(
            "vless://11111111-1111-1111-1111-111111111111@a.example.com:443#V1",
            "hy2://pw@b.example.com:8443#H1",
            "hysteria2://pw@b.example.com:8443#H1-dupe",
            "naive+https://u:p@c.example.com:443#N1",
            "http://d.example.com:8080#HTTP1",
            "https://e.example.com:8443#HTTPS1"
        )
        val hyOnly = ConfigHarvester.filterByProtocol(raw, "hysteria2")
        assertEquals(1, hyOnly.size)
        assertEquals("hy2://pw@b.example.com:8443#H1", hyOnly[0])

        val httpBoth = ConfigHarvester.filterByProtocol(raw, "http/https")
        assertEquals(2, httpBoth.size)

        val sub = ConfigHarvester.toBase64Subscription(httpBoth)
        assertTrue(sub.isNotBlank())
        val roundTripped = UniversalConfig.extractAll(sub)
        assertEquals(2, roundTripped.size)
    }
}
