package com.dastyab.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Hermetic JVM unit tests for [HarvestSourceStore] GitHub blob-to-raw conversion,
 * Telegram channel normalization, bulk parsing, and proxy URI host/port extraction.
 */
class HarvestSourceStoreTest {

    @Test
    fun normalizeGithubUrl_convertsBlobUrlsToRaw() {
        val blob = "https://github.com/WhiteDNS/WhiteVPN/blob/main/configs/sub.txt"
        assertEquals(
            "https://raw.githubusercontent.com/WhiteDNS/WhiteVPN/main/configs/sub.txt",
            HarvestSourceStore.normalizeGithubUrl(blob)
        )
        val alreadyRaw = "https://raw.githubusercontent.com/a/b/main/c.txt"
        assertEquals(alreadyRaw, HarvestSourceStore.normalizeGithubUrl(alreadyRaw))
        assertNull(HarvestSourceStore.normalizeGithubUrl("not-a-url"))
    }

    @Test
    fun normalizeTelegramChannel_handlesAtAndUrls() {
        assertEquals("v2rayng_org", HarvestSourceStore.normalizeTelegramChannel("@v2rayng_org"))
        assertEquals("PrivateVPNs", HarvestSourceStore.normalizeTelegramChannel("https://t.me/s/PrivateVPNs"))
        assertEquals("DirectVPN", HarvestSourceStore.normalizeTelegramChannel("t.me/DirectVPN/1234"))
        assertEquals("whitedns", HarvestSourceStore.normalizeTelegramChannel("Telegram.me/whitedns"))
        assertEquals("whitedns", HarvestSourceStore.normalizeTelegramChannel("https://telegram.me/s/whitedns"))
        assertNull(HarvestSourceStore.normalizeTelegramChannel("a"))
        assertNull(HarvestSourceStore.normalizeTelegramChannel("bad channel!"))
    }

    @Test
    fun parseBulkUrlsAndChannels_deduplicatesAndNormalizes() {
        val urls = HarvestSourceStore.parseBulkGithubUrls(
            "https://github.com/u/r/blob/main/a.txt\nhttps://raw.githubusercontent.com/u/r/main/a.txt, invalid"
        )
        assertEquals(listOf("https://raw.githubusercontent.com/u/r/main/a.txt"), urls)

        val channels = HarvestSourceStore.parseBulkTelegramChannels("@chan_one, https://t.me/s/chan_two\nchan_one")
        assertEquals(listOf("chan_one", "chan_two"), channels)
    }

    @Test
    fun extractHostAndPort_supportsAllProtocols() {
        assertEquals(
            "edge.example.com" to 443,
            HarvestSourceStore.extractHostAndPort("vless://uuid@edge.example.com:443?security=tls")
        )
        assertEquals(
            "tr.example.com" to 8443,
            HarvestSourceStore.extractHostAndPort("trojan://pass@tr.example.com:8443#Node")
        )
        assertEquals(
            "162.159.192.1" to 2408,
            HarvestSourceStore.extractHostAndPort("wireguard://privKey@162.159.192.1:2408?publickey=pub#WARP")
        )
        assertEquals(
            "npv.example.com" to 443,
            HarvestSourceStore.extractHostAndPort("npv4://user@npv.example.com:443#NPV")
        )
        assertEquals(
            "185.1.2.3" to 8443,
            HarvestSourceStore.extractHostAndPort("tg://proxy?server=185.1.2.3&port=8443&secret=dd00")
        )
    }

    @Test
    fun classifySourceInput_andBulkSources_handlesAllFourTypes() {
        val raw = """
            github_raw | Barry VLESS | https://github.com/barry-far/V2ray-Configs/blob/main/Splitted-By-Protocol/vless.txt
            https://sub.example.com/api/v1/client/subscribe?token=abc
            @whitedns
            https://t.me/s/FarazV2ray/12345
        """.trimIndent()
        val parsed = HarvestSourceStore.parseBulkSources(raw)
        assertEquals(4, parsed.size)
        assertEquals(HarvestSourceStore.SourceType.GITHUB_RAW, parsed[0].type)
        assertEquals(
            "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
            parsed[0].value
        )
        assertEquals("Barry VLESS", parsed[0].name)
        assertEquals(HarvestSourceStore.SourceType.SUBSCRIPTION_URL, parsed[1].type)
        assertEquals(HarvestSourceStore.SourceType.TELEGRAM_CHANNEL, parsed[2].type)
        assertEquals("whitedns", parsed[2].value)
        assertEquals(HarvestSourceStore.SourceType.TELEGRAM_POST, parsed[3].type)
        assertEquals("https://t.me/FarazV2ray/12345", parsed[3].value)
    }

    @Test
    fun jsonAndTextExportImport_roundTripsSourcesAndStats() {
        val sources = listOf(
            HarvestSourceStore.HarvestSource(
                id = "github_raw:https://raw.githubusercontent.com/a/b/main/sub.txt",
                name = "Feed A",
                type = HarvestSourceStore.SourceType.GITHUB_RAW,
                value = "https://raw.githubusercontent.com/a/b/main/sub.txt",
                enabled = true,
                isDefault = false,
                lastFetchTimeMs = 1710000000000L,
                configsFound = 42,
                attemptCount = 4,
                successCount = 3
            ),
            HarvestSourceStore.HarvestSource(
                id = "telegram_post:https://t.me/whitedns/99",
                name = "Post 99",
                type = HarvestSourceStore.SourceType.TELEGRAM_POST,
                value = "https://t.me/whitedns/99",
                enabled = false,
                attemptCount = 2,
                successCount = 1
            )
        )
        assertEquals(75, sources[0].successRate)
        assertEquals(50, sources[1].successRate)

        val json = HarvestSourceStore.serializeSourcesJson(sources)
        val restored = HarvestSourceStore.parseSourcesJson(json)
        assertEquals(2, restored.size)
        assertEquals("Feed A", restored[0].name)
        assertEquals(42, restored[0].configsFound)
        assertEquals(75, restored[0].successRate)
        assertEquals(false, restored[1].enabled)
        assertEquals(HarvestSourceStore.SourceType.TELEGRAM_POST, restored[1].type)

        val text = HarvestSourceStore.exportSourcesText(sources)
        val fromText = HarvestSourceStore.parseBulkSources(text)
        assertEquals(2, fromText.size)
    }
}
