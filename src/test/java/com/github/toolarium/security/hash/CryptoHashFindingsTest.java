/*
 * CryptoHashFindingsTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.hash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;


/**
 * Test the fix of the finding N54 of the {@link CryptoHashUtil}: an empty key gives a {@link GeneralSecurityException}.
 *
 * @author patrick
 */
public class CryptoHashFindingsTest {

    /**
     * Constructor for CryptoHashFindingsTest
     */
    public CryptoHashFindingsTest() {
        // NOP
    }


    /**
     * A null or empty key is rejected with a {@link GeneralSecurityException}.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testInvalidKey() throws GeneralSecurityException {
        byte[] data = "data".getBytes(StandardCharsets.UTF_8);
        assertThrows(GeneralSecurityException.class, () -> CryptoHashUtil.getInstance().createHashWithKey(null, new byte[0], data));
        assertThrows(GeneralSecurityException.class, () -> CryptoHashUtil.getInstance().createHashWithKey(null, null, data));

        // a valid key gives the hexadecimal HMAC-SHA256
        assertEquals(64, CryptoHashUtil.getInstance().createHashWithKey(null, new byte[] {1, 2, 3}, data).length);
    }
}
