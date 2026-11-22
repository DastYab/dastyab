package com.dastyab.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hermetic JVM unit tests for [UniversalConfig]:
 *  - WireGuard `.conf` INI <-> `wireguard://` round-trip conversion
 *  - NapsternetV (`npv://`, `npv4://`), VMess, SSR, Shadowsocks (plain, SIP002, Base64)
 *  - Hysteria2 / TUIC / IPv6 WARP / SOCKS5 / SlipNet / Telegram MTProto links
 *  - Inline Base64 subscription blobs inside Telegram HTML
 *  - Protocol-balanced merging (`mergeBalanced`)
 */
class UniversalConfigTest {

    @Test
    fun wireGuardIni_roundTripsThroughUriAndPreservesEndpointAndKeys() {
        val ini = """
            [Interface]
            PrivateKey = cPrivKeyExample1234567890=
            Address = 172.16.0.2/32
            DNS = 1.1.1.1
            MTU = 1280

            [Peer]
            PublicKey = bPubKeyExample0987654321=
            Endpoint = 162.159.192.1:2408
        """.trimIndent()

        val uri = UniversalConfig.wireGuardIniToUri(ini, "WARP-Clean")
        assertNotNull(uri)
        assertTrue(uri!!.startsWith("wireguard://"))

        val parsed = UniversalConfig.parse(uri)
        assertNotNull(parsed)
        assertEquals("wireguard", parsed!!.protocol)
        assertEquals(UniversalConfig.Family.WIREGUARD, parsed.family)
        assertEquals("162.159.192.1", parsed.host)
        assertEquals(2408, parsed.port)

        val rebuiltIni = UniversalConfig.wireGuardUriToIni(uri)
        assertNotNull(rebuiltIni)
        assertTrue(rebuiltIni!!.contains("[Interface]"))
        assertTrue(rebuiltIni.contains("PrivateKey = cPrivKeyExample1234567890="))
        assertTrue(rebuiltIni.contains("[Peer]"))
        assertTrue(rebuiltIni.contains("PublicKey = bPubKeyExample0987654321="))
        assertTrue(rebuiltIni.contains("Endpoint = 162.159.192.1:2408"))
    }

    @Test
    fun parse_supportsNapsternetV_vmess_ssr_shadowsocks_ipv6_and_mtproto() {
        // NapsternetV Base64 JSON
        val npvJson = """{"server":"npv.example.com","port":8443,"uuid":"u-1","remarks":"NpvNode"}"""
        val npvUri = "npv4://${encodeBase64(npvJson)}"
        val npvParsed = UniversalConfig.parse(npvUri)
        assertNotNull(npvParsed)
        assertEquals("npv4", npvParsed!!.protocol)
        assertEquals(UniversalConfig.Family.NAPSTERNETV, npvParsed.family)
        assertEquals("npv.example.com", npvParsed.host)
        assertEquals(8443, npvParsed.port)
        assertEquals("NpvNode", npvParsed.label)

        // VMess Base64 JSON
        val vmessJson = """{"v":"2","ps":"VM-Edge","add":"198.51.100.2","port":"443","id":"uuid-vm"}"""
        val vmessParsed = UniversalConfig.parse("vmess://${encodeBase64(vmessJson)}")
        assertNotNull(vmessParsed)
        assertEquals("vmess", vmessParsed!!.protocol)
        assertEquals("198.51.100.2", vmessParsed.host)
        assertEquals(443, vmessParsed.port)
        assertEquals("VM-Edge", vmessParsed.label)

        // SSR Base64
        val ssrPlain = "95.85.234.66:10001:auth_aes128_md5:aes-128-ctr:tls1.2_ticket_auth:Zm9vYmFy"
        val ssrParsed = UniversalConfig.parse("ssr://${encodeBase64(ssrPlain)}#SSRNode")
        assertNotNull(ssrParsed)
        assertEquals("ssr", ssrParsed!!.protocol)
        assertEquals("95.85.234.66", ssrParsed.host)
        assertEquals(10001, ssrParsed.port)

        // Shadowsocks SIP002 + Full Base64
        val sip002User = encodeBase64("aes-256-gcm:pass123")
        val ssSip = UniversalConfig.parse("ss://$sip002User@10.20.30.40:8388#London")
        assertNotNull(ssSip)
        assertEquals("10.20.30.40", ssSip!!.host)
        assertEquals(8388, ssSip.port)

        val ssFull = UniversalConfig.parse("ss://${encodeBase64("chacha20-ietf-poly1305:pw@5.6.7.8:9443")}#FullSS")
        assertNotNull(ssFull)
        assertEquals("5.6.7.8", ssFull!!.host)
        assertEquals(9443, ssFull.port)

        // IPv6 WARP / Hysteria2 / SlipNet / MTProto
        val warp6 = UniversalConfig.parse("warp://[2606:4700:d0::a29f:c001]:2408#WARPv6")
        assertNotNull(warp6)
        assertEquals("2606:4700:d0::a29f:c001", warp6!!.host)
        assertEquals(2408, warp6.port)

        val hy2 = UniversalConfig.parse("hy2://token@hy.example.com:8443?sni=hy.example.com#Hy2")
        assertNotNull(hy2)
        assertEquals("hy2", hy2!!.protocol)
        assertEquals(8443, hy2.port)

        val mt = UniversalConfig.parse("tg://proxy?server=185.1.2.3&port=443&secret=dd000011")
        assertNotNull(mt)
        assertEquals("mtproto", mt!!.protocol)
        assertEquals(UniversalConfig.Family.TELEGRAM_MTPROTO, mt.family)
        assertEquals("185.1.2.3", mt.host)
        assertEquals(443, mt.port)

        assertNull(UniversalConfig.parse("https://example.com/not-a-proxy"))
        assertNull(UniversalConfig.parse("http://example.com/not-a-proxy"))
    }

    @Test
    fun extractAll_harvestsTelegramHtmlWireGuardIniInlineBase64AndIgnoresUnknownSchemes() {
        val innerSub = """
            npv://auth@npv-sub.example.com:443#NpvSub
            hy2://pw@hy-sub.example.com:8443#HySub
        """.trimIndent()
        val html = """
            <div class="tgme_widget_message_text">
                bypass://user@ignored.example.com:443<br/>
                [Interface]<br/>
                PrivateKey = privKey1234567890=<br/>
                Address = 10.0.0.2/32<br/>
                [Peer]<br/>
                PublicKey = pubKey1234567890=<br/>
                Endpoint = 162.159.193.1:500<br/>
                https://t.me/proxy?server=1.2.3.4&amp;port=8443&amp;secret=ee12345678<br/>
                ${encodeBase64(innerSub)}
            </div>
        """.trimIndent()

        val extracted = UniversalConfig.extractAll(html)
        assertTrue(extracted.any { it.startsWith("wireguard://privKey1234567890%3D@162.159.193.1:500") })
        assertTrue(extracted.any { it == "https://t.me/proxy?server=1.2.3.4&port=8443&secret=ee12345678" })
        assertTrue(extracted.any { it.startsWith("npv://auth@npv-sub.example.com:443") })
        assertTrue(extracted.any { it.startsWith("hy2://pw@hy-sub.example.com:8443") })
        assertTrue(extracted.none { it.contains("ignored.example.com") })
    }

    @Test
    fun mergeBalanced_preservesNonVlessDiversityUnderCap() {
        val list = mutableListOf<String>()
        for (i in 1..20) {
            list += "vless://uuid-$i@v$i.example.com:443#v$i"
        }
        list += "wireguard://pk@162.159.192.1:2408#wg"
        list += "npv4://u@npv.example.com:443#npv"
        list += "tg://proxy?server=1.2.3.4&port=443&secret=dd00#mt"

        val balanced = UniversalConfig.mergeBalanced(list, limit = 6)
        assertEquals(6, balanced.size)
        assertTrue(balanced.any { it.startsWith("wireguard://") })
        assertTrue(balanced.any { it.startsWith("npv4://") })
        assertTrue(balanced.any { it.startsWith("tg://proxy") })
    }

    @Test
    fun openVpn_extractsDirectivesAndRoundTripsOvpnAndNpvs() {
        val rawOvpn = """
            client
            dev tun
            proto tcp
            remote 45.77.12.90 443
            cipher AES-256-GCM
        """.trimIndent()
        val uris = UniversalConfig.extractAll(rawOvpn)
        assertTrue(uris.any { it.startsWith("openvpn://45.77.12.90:443") })
        val parsed = UniversalConfig.parse(uris.first { it.startsWith("openvpn://") })
        assertNotNull(parsed)
        assertEquals(UniversalConfig.Family.OPENVPN, parsed!!.family)
        assertEquals("45.77.12.90", parsed.host)
        assertEquals(443, parsed.port)

        val rebuiltOvpn = UniversalConfig.openVpnUriToOvpn(parsed.uri)
        assertNotNull(rebuiltOvpn)
        assertTrue(rebuiltOvpn!!.contains("remote 45.77.12.90 443"))
        assertTrue(rebuiltOvpn.contains("proto tcp"))

        val npvs = UniversalConfig.parse("npvs://user@npvs.example.com:8443#NPVS")
        assertNotNull(npvs)
        assertEquals(UniversalConfig.Family.NAPSTERNETV, npvs!!.family)
        assertEquals(8443, npvs.port)

        val npvUnpaddedJson = """{"address":"addr.example.com","serverPort":9443,"remarks":"UnpaddedNpv"}"""
        val npvUnpaddedB64 = encodeBase64(npvUnpaddedJson).trimEnd('=')
        val npvUnpadded = UniversalConfig.parse("npv4://$npvUnpaddedB64")
        assertNotNull(npvUnpadded)
        assertEquals("addr.example.com", npvUnpadded!!.host)
        assertEquals(9443, npvUnpadded.port)
        assertEquals("UnpaddedNpv", npvUnpadded.label)
    }

    @Test
    fun mtproto_acceptsSupportedFormsAndRejectsMalformedForms() {
        val validLinks = listOf(
            "tg://proxy?server=1.2.3.4&port=443&secret=dd00001111",
            "https://t.me/proxy?server=1.2.3.4&port=443&secret=dd00001111",
            "http://t.me/proxy?server=1.2.3.4&port=443&secret=dd00001111",
            "https://telegram.me/proxy?server=1.2.3.4&port=443&secret=dd00001111",
            "http://telegram.me/proxy?server=1.2.3.4&port=443&secret=dd00001111",
            "HTTPS://T.ME/PROXY?server=1.2.3.4&port=443&secret=dd00001111",
            "TG://PROXY?host=1.2.3.4&port=443&secret=dd00001111"
        )
        for (link in validLinks) {
            assertTrue("Expected isMtProtoUri for $link", UniversalConfig.isMtProtoUri(link))
            val parsed = UniversalConfig.parse(link)
            assertNotNull("Expected non-null parse for $link", parsed)
            assertEquals("mtproto", parsed!!.protocol)
            assertEquals(UniversalConfig.Family.TELEGRAM_MTPROTO, parsed.family)
            assertEquals("1.2.3.4", parsed.host)
            assertEquals(443, parsed.port)
        }

        val withFrag = UniversalConfig.parse("tg://proxy?server=1.2.3.4&port=8443&secret=ee12#FastTag")
        assertNotNull(withFrag)
        assertEquals(8443, withFrag!!.port)
        assertEquals("FastTag", withFrag.label)

        val malformedLinks = listOf(
            "https://evil.example/t.me/proxy?server=1.2.3.4&port=443&secret=abc",
            "https://evil.example/https://t.me/proxy?server=1.2.3.4&port=443&secret=abc",
            "ftp://t.me/proxy?server=1.2.3.4&port=443&secret=abc",
            "tg://proxyevil?server=1.2.3.4&port=443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=0&secret=abc",
            "tg://proxy?server=1.2.3.4&port=65536&secret=abc",
            "tg://proxy?server=1.2.3.4&port=abc&secret=abc",
            "tg://proxy?server=1.2.3.4&secret=abc",
            "tg://proxy?port=443&secret=abc",
            "tg://proxy?server=%20%20&port=443&secret=abc",
            "tg://proxy?server=1.2.3.4/path&port=443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=443",
            "tg://proxy?server=1.2.3.4&port=443&secret=",
            "tg://proxy?server=1.2.3.4&port=443&secret=%20",
            "tg://proxy?server=1.2.3.4&server=5.6.7.8&port=443&secret=abc",
            "tg://proxy?server=1.2.3.4&host=5.6.7.8&port=443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=443&port=8443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=443&secret=abc&secret=def",
            "tg://proxy?server=1.2.3.4&port=443&secret=abc&extra=1",
            "tg://proxy?server=1.2.3.4&port=443&secret=abc&dangling",
            "tg://proxy?server=1.2.3.4&port=+443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=%2B443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=%20443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=443%20&secret=abc",
            "tg://proxy?server=1.2.3.4&port=%ZZ&secret=abc",
            "tg://proxy?server=1.2.3.4%23bad&port=443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=443&secret=ab%20cd"
        )
        for (bad in malformedLinks) {
            assertNull("Expected null for $bad", UniversalConfig.parse(bad))
        }

        val html = """
            <a href="HTTPS://T.ME/PROXY?server=1.2.3.4&amp;port=443&amp;secret=abc">p</a>
            <span>(tg://proxy?server=5.6.7.8&amp;port=8443&amp;secret=def),</span>
            <a href="https://evil.example/t.me/proxy?server=9.9.9.9&amp;port=443&amp;secret=bad">x</a>
            <a href="https://evil.example/https://t.me/proxy?server=8.8.8.8&amp;port=443&amp;secret=bad">y</a>
            <span>tg://proxy?server=7.7.7.7&amp;port=443</span>
        """.trimIndent()
        val extracted = UniversalConfig.extractAll(html)
        assertEquals(
            listOf(
                "tg://proxy?server=5.6.7.8&port=8443&secret=def",
                "HTTPS://T.ME/PROXY?server=1.2.3.4&port=443&secret=abc"
            ),
            extracted
        )
    }

    private fun encodeBase64(text: String): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val bytes = text.toByteArray(Charsets.UTF_8)
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

    @Test
    fun extractProxyListHops_parsesMixedFormatsFiltersLoopbackAndSpreadsSubnets() {
        val raw = """
            127.0.0.1:8080
            0.0.0.0:1080
            198.51.100.1:1080
            198.51.100.2:1080
            203.0.113.5:3128
            http://u1:p1@192.0.2.10:8080
            tg://socks?server=185.10.20.30&port=443&user=tg&pass=ok
        """.trimIndent()

        val hops = UniversalConfig.extractProxyListHops(raw, defaultScheme = TunnelConfig.ProxyScheme.SOCKS5, maxHops = 20)
        assertEquals(5, hops.size)
        assertTrue(hops.none { it.host == "127.0.0.1" || it.host == "0.0.0.0" })
        assertTrue(hops.any { it.scheme == TunnelConfig.ProxyScheme.HTTP && it.host == "192.0.2.10" && it.username == "u1" })
        assertTrue(hops.any { it.scheme == TunnelConfig.ProxyScheme.SOCKS5 && it.host == "185.10.20.30" && it.password == "ok" })

        // First 4 picked hops must come from distinct /16 subnets
        val firstFourSubnets = hops.take(4).map { UniversalConfig.subnet16Of(it.host) }.toSet()
        assertEquals(4, firstFourSubnets.size)

        // Respect excludedHosts & deprioritize excludedSubnets16
        val filtered = UniversalConfig.selectDiverseProxyHops(
            hops = hops,
            limit = 4,
            excludedHosts = setOf("203.0.113.5"),
            excludedSubnets16 = setOf("198.51")
        )
        assertTrue(filtered.none { it.host == "203.0.113.5" })
        assertTrue(
            "Fresh subnets must come before excluded /16 subnet 198.51",
            UniversalConfig.subnet16Of(filtered.first().host) != "198.51"
        )
    }

    @Test
    fun extractChainableProxyHops_honorsLimitAndDeduplicates() {
        val configs = listOf(
            "socks5://198.51.100.1:1080",
            "socks5://198.51.100.1:1080",
            "http://198.51.100.2:8080",
            "socks5://198.51.100.3:1080",
            "vless://11111111-1111-1111-1111-111111111111@203.0.113.1:443?security=tls"
        )
        val unlimited = UniversalConfig.extractChainableProxyHops(configs)
        assertEquals(3, unlimited.size)
        val capped = UniversalConfig.extractChainableProxyHops(configs, limit = 2)
        assertEquals(2, capped.size)
    }

    @Test
    fun extractAll_handles619ServerPersianTelegramTxtDropAndExcludesWebUrls() {
        val sb = StringBuilder()
        sb.appendLine("داخل فایل 619 عدد سرور از تمام کشورها هست ری اکشن فراموش نکنید")
        sb.appendLine("مخابرات و تمام اپراتورها")
        sb.appendLine("بااین برنامه اجرا کنید PattNG (https://t.me/proxy_kafee/48582?single)👉👉 کیلیک کنید")
        sb.appendLine("#ویتوری #v2box #pattNG")
        sb.appendLine("@proxy_kafee")
        sb.appendLine("🔗لینک دانلود نسخه جدید https://github.com/patterniha/PattNG/releases/tag/2.3.8-P50")
        sb.appendLine("🔺آموزش fragment+fingerprint (https://t.me/proxy_kafee/46097)")
        for (i in 1..619) {
            when (i % 5) {
                0 -> sb.appendLine("warp://privKey$i@162.159.192.${(i % 250) + 1}:2408?publickey=pubKey$i#WARP-$i")
                1 -> sb.appendLine("hy2://pass$i@hy$i.example.com:8443?sni=hy$i.example.com#Hy2-$i")
                2 -> sb.appendLine("trojan://secret$i@tr$i.example.com:443?sni=tr$i.example.com#Trojan-$i")
                3 -> sb.appendLine("socks5://user$i:pass$i@198.51.100.${(i % 250) + 1}:1080#Socks-$i")
                else -> sb.appendLine("vless://11111111-2222-3333-4444-${String.format("%012d", i)}@edge$i.example.com:443?security=tls&type=ws#Vless-$i")
            }
        }
        val extracted = UniversalConfig.extractAll(sb.toString())
        assertEquals(619, extracted.size)
        assertTrue(extracted.none { it.contains("proxy_kafee") || it.contains("github.com") })
        assertTrue(UniversalConfig.isNonProxyHttpUrl("https://t.me/proxy_kafee/48582?single"))
        assertTrue(UniversalConfig.isNonProxyHttpUrl("https://github.com/patterniha/PattNG/releases/tag/2.3.8-P50"))
    }

    @Test
    fun buildXrayChainConfigJson_chainsWarpEntryIntoExitOutboundWithFragmentAndFingerprint() {
        val warpEntry = "warp://privKey123@162.159.192.1:2408?publickey=pubKey123#WARP"
        val exitVless = "vless://11111111-2222-3333-4444-555555555555@exit.example.com:443?security=tls&type=ws&sni=exit.example.com#Exit"
        val json = UniversalConfig.buildXrayChainConfigJson(warpEntry, exitVless, socksPort = 10808)
        assertTrue(json.contains("\"protocol\":\"wireguard\""))
        assertTrue(json.contains("\"dialerProxy\":\"entry\""))
        assertTrue(json.contains("\"fingerprint\":\"chrome\""))
        assertTrue(json.contains("\"fragment\""))
    }
}
