package com.dastyab.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Hermetic JVM unit tests for [AppAutoUpdater]:
 * semantic version comparison, device ABI APK selection, SHA-256 sum parsing,
 * GitHub latest-redirect tag parsing, and check throttle logic.
 */
class AppAutoUpdaterTest {

    @Test
    fun compareVersions_handlesTagsPrefixesAndMultiDigitComponents() {
        assertTrue(AppAutoUpdater.compareVersions("v0.3.3", "0.3.2") > 0)
        assertTrue(AppAutoUpdater.compareVersions("v0.10.0", "0.3.2") > 0)
        assertTrue(AppAutoUpdater.compareVersions("1.0", "0.9.9") > 0)
        assertEquals(0, AppAutoUpdater.compareVersions("v0.3.2", "0.3.2"))
        assertEquals(0, AppAutoUpdater.compareVersions("0.3.2-rc1", "v0.3.2"))
        assertTrue(AppAutoUpdater.compareVersions("0.3.1", "0.3.2") < 0)
    }

    @Test
    fun selectBestApkAsset_prefersDeviceAbiThenUniversalFallback() {
        val assets = listOf(
            AppAutoUpdater.ApkAsset("DastYab-0.4.0-android.apk", "https://example/universal.apk"),
            AppAutoUpdater.ApkAsset("DastYab-0.4.0-arm64-v8a.apk", "https://example/arm64.apk"),
            AppAutoUpdater.ApkAsset("DastYab-0.4.0-x86_64.apk", "https://example/x86_64.apk"),
            AppAutoUpdater.ApkAsset("DastYab-0.4.0-debug.apk", "https://example/debug.apk"),
            AppAutoUpdater.ApkAsset("dastyab-linux-amd64", "https://example/linux")
        )

        val pickedArm64 = AppAutoUpdater.selectBestApkAsset(assets, arrayOf("arm64-v8a", "armeabi-v7a"))
        assertEquals("DastYab-0.4.0-arm64-v8a.apk", pickedArm64?.name)

        val pickedX64 = AppAutoUpdater.selectBestApkAsset(assets, arrayOf("x86_64", "x86"))
        assertEquals("DastYab-0.4.0-x86_64.apk", pickedX64?.name)

        // When device ABI has no split APK, fall back to universal APK (never debug/non-APK).
        val universalOnly = listOf(
            AppAutoUpdater.ApkAsset("DastYab-0.4.0-debug.apk", "https://example/debug.apk"),
            AppAutoUpdater.ApkAsset("DastYab-0.4.0-android.apk", "https://example/universal.apk"),
            AppAutoUpdater.ApkAsset("SHA256SUMS.txt", "https://example/sums")
        )
        val pickedFallback = AppAutoUpdater.selectBestApkAsset(universalOnly, arrayOf("armeabi-v7a"))
        assertEquals("DastYab-0.4.0-android.apk", pickedFallback?.name)
    }

    @Test
    fun parseTagAndSha256Sums_workCleanly() {
        assertEquals(
            "v0.4.2",
            AppAutoUpdater.parseTagFromReleaseUrl("https://github.com/DastYab/dastyab/releases/tag/v0.4.2")
        )
        assertNull(AppAutoUpdater.parseTagFromReleaseUrl("https://github.com/DastYab/dastyab/releases/latest"))

        val validDigest = "a".repeat(64)
        val sums = """
            $validDigest  DastYab-0.4.2-android.apk
            0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef *other.bin
        """.trimIndent()
        assertEquals(validDigest, AppAutoUpdater.parseSha256Sums(sums, "DastYab-0.4.2-android.apk"))
        assertNull(AppAutoUpdater.parseSha256Sums(sums, "missing.apk"))
    }

    @Test
    fun throttleAndApkMagicChecksWork() {
        assertTrue(AppAutoUpdater.isCheckDue(0L, 10_000L))
        assertFalse(AppAutoUpdater.isCheckDue(1_000L, 1_000L + 60_000L, 3_600_000L))
        assertTrue(AppAutoUpdater.isCheckDue(1_000L, 1_000L + 3_600_000L, 3_600_000L))

        val tmpZip = File.createTempFile("dastyab-test-", ".apk")
        try {
            val payload = ByteArray(70 * 1024)
            payload[0] = 0x50
            payload[1] = 0x4B
            payload[2] = 0x03
            payload[3] = 0x04
            tmpZip.writeBytes(payload)
            assertTrue(AppAutoUpdater.isPlausibleApkFile(tmpZip))

            payload[0] = '<'.code.toByte()
            tmpZip.writeBytes(payload)
            assertFalse(AppAutoUpdater.isPlausibleApkFile(tmpZip))
        } finally {
            tmpZip.delete()
        }
    }
}
