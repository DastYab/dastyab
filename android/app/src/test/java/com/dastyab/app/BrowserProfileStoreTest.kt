package com.dastyab.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hermetic JVM unit tests for [BrowserProfileStore]:
 * isolated Google account creation, WebKit Profile naming, active switching,
 * deletion guardrails, detected email formatting, and legacy cookie-jar codec.
 */
class BrowserProfileStoreTest {

    @Test
    fun defaultState_preservesDefaultWebkitProfileName() {
        val state = BrowserProfileStore.defaultState()
        assertEquals(1, state.profiles.size)
        val first = state.activeProfile()
        assertEquals(BrowserProfileStore.DEFAULT_PROFILE_ID, first.id)
        assertEquals(BrowserProfileStore.DEFAULT_WEBKIT_PROFILE, first.webkitName)
    }

    @Test
    fun createSwitchRenameAndDetectEmail_workCleanly() {
        val s0 = BrowserProfileStore.defaultState()
        val (s1, p2) = BrowserProfileStore.createProfile(s0, "Work Google", nowMs = 100L)
        assertEquals(2, s1.profiles.size)
        assertEquals(p2.id, s1.activeProfileId)
        assertNotEquals(BrowserProfileStore.DEFAULT_WEBKIT_PROFILE, p2.webkitName)
        assertNotEquals(s0.activeProfile().colorHex, p2.colorHex)

        val s2 = BrowserProfileStore.switchProfile(s1, s0.activeProfileId)
        assertEquals(s0.activeProfileId, s2.activeProfileId)

        val s3 = BrowserProfileStore.renameProfile(s2, p2.id, "Personal Studio")
        assertEquals("Personal Studio", s3.profiles.first { it.id == p2.id }.name)

        val s4 = BrowserProfileStore.updateDetectedEmail(s3, p2.id, "alice@gmail.com")
        val updatedP2 = s4.profiles.first { it.id == p2.id }
        assertEquals("alice@gmail.com", updatedP2.detectedEmail)
        assertEquals("A", BrowserProfileStore.avatarInitial(updatedP2))
    }

    @Test
    fun deleteProfile_neverRemovesLastProfile_andFallsBackWhenActiveRemoved() {
        val s0 = BrowserProfileStore.defaultState()
        val onlyBlocked = BrowserProfileStore.deleteProfile(s0, s0.activeProfileId)
        assertNull(onlyBlocked.removed)
        assertNotNull(onlyBlocked.rejectedReason)
        assertEquals(1, onlyBlocked.state.profiles.size)

        val (s1, p2) = BrowserProfileStore.createProfile(s0, "Alt Account")
        val (s2, p3) = BrowserProfileStore.createProfile(s1, "Third Account")
        assertEquals(p3.id, s2.activeProfileId)

        val delRes = BrowserProfileStore.deleteProfile(s2, p3.id)
        assertEquals(p3.id, delRes.removed?.id)
        assertEquals(2, delRes.state.profiles.size)
        assertEquals(p2.id, delRes.state.activeProfileId)
    }

    @Test
    fun cookieJarCodec_roundTripsArbitraryGoogleCookies() {
        val input = linkedMapOf(
            "https://accounts.google.com" to "SID=abc=123; HSID=xyz\t456",
            "https://aistudio.google.com" to "__Secure-1PSID=tok_999"
        )
        val encoded = BrowserProfileStore.encodeCookieJarEntries(input)
        val decoded = BrowserProfileStore.decodeCookieJarEntries(encoded)
        assertEquals(input, decoded)
        assertTrue(BrowserProfileStore.formatHostForOmnibar("https://aistudio.google.com/app/prompts").startsWith("aistudio.google.com"))
    }
}
