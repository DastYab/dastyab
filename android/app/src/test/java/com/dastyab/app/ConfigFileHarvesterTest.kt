package com.dastyab.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hermetic JVM unit tests for [ConfigFileHarvester] URL & Telegram attachment discovery,
 * `.ovpn` / `.conf` / Clash YAML / Sing-box JSON endpoint extraction, and vault serialization.
 */
class ConfigFileHarvesterTest {

    @Test
    fun extractChannelFiles_capturesAllConfigExtensionsAndTelegramDocuments() {
        val html = """
            <div class="tgme_widget_message_wrap">
                <a href="https://cdn.example.com/vpn/iran_fast.ovpn">OVPN</a>
                <a href="https://cdn.example.com/vpn/warp.openvpn?dl=1">OpenVPN</a>
                <a href="https://cdn.example.com/vpn/mci.npvs">NPVS</a>
                <a href="https://cdn.example.com/vpn/server.hc">HC</a>
                <a href="https://cdn.example.com/vpn/bypass.custom">Custom</a>
                <a href="https://cdn.example.com/vpn/alt.costum">Costum</a>
                <a href="https://cdn.example.com/vpn/ssh.dark">Dark</a>
                <a href="https://cdn.example.com/vpn/sni.tls">TLS</a>
                https://raw.githubusercontent.com/user/repo/main/wg_clean.conf
            </div>
            <div class="tgme_widget_message_wrap" data-post="ConfigWireguard/441">
                <div class="tgme_widget_message_document_title">irancell_turbo.npvs</div>
                <div class="tgme_widget_message_document_extra">18.4 KB</div>
            </div>
            <div class="tgme_widget_message_wrap" data-post="ConfigX2ray/902">
                <div class="tgme_widget_message_document_title">hamrah_hc.hc</div>
            </div>
        """.trimIndent()

        val found = ConfigFileHarvester.extractChannelFiles(html, "@ConfigWireguard")
        val exts = found.map { it.extension }.toSet()
        assertTrue("ovpn" in exts)
        assertTrue("openvpn" in exts)
        assertTrue("npvs" in exts)
        assertTrue("hc" in exts)
        assertTrue("custom" in exts)
        assertTrue("costum" in exts)
        assertTrue("dark" in exts)
        assertTrue("tls" in exts)
        assertTrue("conf" in exts)

        val tgNpv = found.firstOrNull { it.fileName == "irancell_turbo.npvs" }
        assertEquals("https://t.me/ConfigWireguard/441", tgNpv?.postUrl)
    }

    @Test
    fun extractEndpointsFromFileText_parsesOvpnConfJsonAndYaml() {
        val ovpn = """
            client
            dev tun
            proto tcp
            remote 45.88.12.34 443
            nobind
        """.trimIndent()
        val ovpnEndpoints = ConfigFileHarvester.extractEndpointsFromFileText("mci.ovpn", ovpn)
        assertTrue(ovpnEndpoints.any { it.startsWith("openvpn://45.88.12.34:443") })

        val singboxJson = """
            {
              "outbounds": [
                {"type": "hysteria2", "server": "hy.example.com", "server_port": 8443},
                {"type": "wireguard", "server": "162.159.192.1", "server_port": 2408}
              ]
            }
        """.trimIndent()
        val jsonEndpoints = ConfigFileHarvester.extractEndpointsFromFileText("box.json", singboxJson)
        assertTrue(jsonEndpoints.any { it.contains("hy.example.com:8443") })
        assertTrue(jsonEndpoints.any { it.contains("162.159.192.1:2408") })

        val clashYaml = """
            proxies:
              - {name: "Fast-Trojan", type: trojan, server: tr.example.com, port: 443}
              - {name: "Fast-SOCKS", type: socks5, server: 10.10.10.5, port: 1080}
        """.trimIndent()
        val yamlEndpoints = ConfigFileHarvester.extractEndpointsFromFileText("clash.yaml", clashYaml)
        assertTrue(yamlEndpoints.any { it.contains("tr.example.com:443") })
        assertTrue(yamlEndpoints.any { it.contains("10.10.10.5:1080") })
    }

    @Test
    fun vaultSerialization_roundTripsCleanly() {
        val sample = listOf(
            ConfigFileHarvester.VaultEntry(
                id = "f1",
                fileName = "iran_fast.ovpn",
                extension = "ovpn",
                localPath = "/tmp/iran_fast.ovpn",
                sourceLabel = "@whitedns",
                downloadUrl = "https://example.com/iran_fast.ovpn",
                postUrl = "https://t.me/whitedns/55",
                sizeBytes = 2048L,
                extractedEndpoints = 1,
                createdAtMs = 1700000000000L
            )
        )
        val raw = ConfigFileHarvester.serializeVault(sample)
        val restored = ConfigFileHarvester.deserializeVault(raw)
        assertEquals(1, restored.size)
        assertEquals("iran_fast.ovpn", restored[0].fileName)
        assertEquals("ovpn", restored[0].extension)
        assertEquals("@whitedns", restored[0].sourceLabel)
        assertEquals(2048L, restored[0].sizeBytes)
    }

    @Test
    fun extractChannelFiles_acceptsArbitraryTxtAndRejectsNoiseTxt() {
        val html = """
            <a href="https://cdn.example.com/drops/all_619_servers.txt">Drop</a>
            <a href="https://cdn.example.com/robots.txt">Robots</a>
            <a href="https://cdn.example.com/README.txt">Readme</a>
            <a href="https://cdn.example.com/wg.awg">AWG</a>
            <a href="https://cdn.example.com/nodes.sbox">SBOX</a>
        """.trimIndent()
        val found = ConfigFileHarvester.extractChannelFiles(html, "@proxy_kafee")
        val names = found.map { it.fileName }.toSet()
        assertTrue("all_619_servers.txt" in names)
        assertTrue("wg.awg" in names)
        assertTrue("nodes.sbox" in names)
        assertTrue("robots.txt" !in names)
        assertTrue("README.txt" !in names)
    }

    @Test
    fun extractEndpointsFromFileBytes_handlesUtf16AndBlockYamlAndBinaryPrintable() {
        val text = """
            proxies:
              - name: "MultiLine-Hy2"
                type: hysteria2
                server: ml-hy2.example.com
                port: 8443
                password: secret
        """.trimIndent()
        val utf16Bytes = byteArrayOf(0xFF.toByte(), 0xFE.toByte()) + text.toByteArray(Charsets.UTF_16LE)
        val extracted = ConfigFileHarvester.extractEndpointsFromFileBytes("drop.txt", utf16Bytes)
        assertTrue(extracted.any { it.contains("ml-hy2.example.com:8443") })

        val binPayload = byteArrayOf(0x00, 0x01, 0x7F.toByte()) +
            "trojan://pass123@bin-tr.example.com:443#BinTrojan".toByteArray(Charsets.UTF_8) +
            byteArrayOf(0x00, 0x02)
        val binExtracted = ConfigFileHarvester.extractEndpointsFromFileBytes("packed.npvt", binPayload)
        assertTrue(binExtracted.any { it.contains("bin-tr.example.com:443") })
    }
}
