package io.github.vrlmvg.auth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OtpAuthUriParserTest {
    @Test
    fun parseStandardGoogleUri() {
        val result = OtpAuthUriParser.parse(
            "otpauth://totp/Google:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Google",
        )

        val account = result.getOrThrow()
        assertEquals("Google", account.issuer)
        assertEquals("user@example.com", account.label)
        assertEquals("JBSWY3DPEHPK3PXP", account.secret)
        assertEquals(6, account.digits)
        assertEquals(30, account.period)
        assertEquals(TotpAlgorithm.SHA1, account.algorithm)
    }

    @Test
    fun parseIssuerFromPath() {
        val result = OtpAuthUriParser.parse(
            "otpauth://totp/AWS:admin?secret=ABCDEFGH&digits=8&period=60",
        )

        val account = result.getOrThrow()
        assertEquals("AWS", account.issuer)
        assertEquals("admin", account.label)
        assertEquals(8, account.digits)
        assertEquals(60, account.period)
    }

    @Test
    fun parseAlgorithmParam() {
        val result = OtpAuthUriParser.parse(
            "otpauth://totp/Example?secret=ABCDEFGH&algorithm=SHA256",
        )

        val account = result.getOrThrow()
        assertEquals(TotpAlgorithm.SHA256, account.algorithm)
    }

    @Test
    fun rejectsNonOtpauthUri() {
        val result = OtpAuthUriParser.parse("https://example.com")
        assertTrue(result.isFailure)
    }

    @Test
    fun malformedInputFailsInsteadOfThrowing() {
        for (uri in listOf(
            "otpauth://totp/Bad%zzEscape?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/Example?secret=not-base32!",
            "otpauth://totp/Example?secret=",
            "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=12",
            "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/[broken",
        )) {
            assertTrue(OtpAuthUriParser.parse(uri).isFailure, uri)
        }
    }

    @Test
    fun acceptsUnescapedSpaces() {
        val account = OtpAuthUriParser.parse("otpauth://totp/My Bank:me?secret=JBSWY3DPEHPK3PXP&issuer=My Bank").getOrThrow()
        assertEquals("My Bank", account.issuer)
        assertEquals("me", account.label)
    }
}
