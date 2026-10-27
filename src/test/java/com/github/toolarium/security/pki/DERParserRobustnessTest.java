/*
 * DERParserRobustnessTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import com.github.toolarium.security.pki.impl.rsa.der.DERInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.Test;


/**
 * Tests the DER parser with malformed input: it must fail fast with a checked exception.
 *
 * @author patrick
 */
public class DERParserRobustnessTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(10);


    /**
     * Constructor for DERParserRobustnessTest
     */
    public DERParserRobustnessTest() {
        // NOP
    }


    /**
     * A negative long-form length inside an indefinite-length sequence must not cause an endless loop (N9).
     */
    @Test
    public void testNegativeLengthInIndefiniteSequence() {
        assertInvalidRSAPrivateKey(new byte[] {0x30, (byte) 0x80, 0x02, (byte) 0x84, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFA, 0x00});
    }


    /**
     * A length exceeding the remaining data inside an indefinite-length sequence must be rejected (N9).
     */
    @Test
    public void testExcessiveLengthInIndefiniteSequence() {
        assertInvalidRSAPrivateKey(new byte[] {0x30, (byte) 0x80, 0x04, (byte) 0x84, 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00});
    }


    /**
     * An indefinite-length sequence without end-of-contents must be rejected (N9).
     */
    @Test
    public void testUnterminatedIndefiniteSequence() {
        assertInvalidRSAPrivateKey(new byte[] {0x30, (byte) 0x80, 0x02, 0x01, 0x00});
    }


    /**
     * An empty sequence must be rejected.
     */
    @Test
    public void testEmptySequence() {
        assertInvalidRSAPrivateKey(new byte[] {0x30, 0x00});
    }


    /**
     * A zero-length integer must be rejected (N29).
     */
    @Test
    public void testZeroLengthInteger() {
        assertInvalidRSAPrivateKey(new byte[] {0x30, 0x03, 0x02, 0x00, 0x00});
    }


    /**
     * A truncated long-form length must be rejected instead of being read as 0xFF (N29).
     */
    @Test
    public void testTruncatedLength() {
        assertThrows(IOException.class, () -> DERInputStream.getLength(new ByteArrayInputStream(new byte[] {(byte) 0x82, 0x01})));
        assertThrows(IOException.class, () -> DERInputStream.getLength(new ByteArrayInputStream(new byte[0])));
    }


    /**
     * Asserts that the given DER content is rejected as RSA private key with a {@link GeneralSecurityException} in time.
     *
     * @param der the DER content
     */
    private void assertInvalidRSAPrivateKey(byte[] der) {
        final String content = Base64.getEncoder().encodeToString(der);
        assertTimeoutPreemptively(TIMEOUT, () -> {
            assertThrows(GeneralSecurityException.class, () -> KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).getPrivateKey(content));
        });
    }
}
