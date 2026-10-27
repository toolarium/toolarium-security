/*
 * CryptUtilTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.github.toolarium.security.cryption.util.CryptionUtil;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;


/**
 * Test the deprecated {@link CryptUtil}: it delegates to the {@link CryptionUtil} and gives the same results.
 *
 * @author patrick
 */
@SuppressWarnings("deprecation")
public class CryptUtilTest {
    private static final String PASSPHRASE = "my-test-passphrase";


    /**
     * Constructor for CryptUtilTest
     */
    public CryptUtilTest() {
        // NOP
    }


    /**
     * The deprecated class derives the same keys as the new class.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testDelegation() throws GeneralSecurityException {
        assertEquals(CryptionUtil.ALGORITHM_AES, CryptUtil.ALGORITHM_AES);
        assertEquals(CryptionUtil.getInstance().isStrongEncryptionEnabled(), CryptUtil.getInstance().isStrongEncryptionEnabled());
        assertEquals(CryptionUtil.getInstance().getMaxAllowedKeyLength("AES"), CryptUtil.getInstance().getMaxAllowedKeyLength("AES"));
        assertEquals(CryptionUtil.getInstance().getAlgorithmMessage("SunJCE", "AES/GCM/NoPadding"), CryptUtil.getInstance().getAlgorithmMessage("SunJCE", "AES/GCM/NoPadding"));
        assertEquals(16, CryptUtil.getInstance().generateSalt().length);

        assertArrayEquals(CryptionUtil.getInstance().createSecretKeySpec(PASSPHRASE.toCharArray()).getEncoded(),
                          CryptUtil.getInstance().createSecretKeySpec(PASSPHRASE.toCharArray()).getEncoded());

        byte[] salt = CryptionUtil.getInstance().generateSalt();
        assertArrayEquals(CryptionUtil.getInstance().createSecretKeySpec(PASSPHRASE.toCharArray(), salt, 1000).getEncoded(),
                          CryptUtil.getInstance().createSecretKeySpec(PASSPHRASE.toCharArray(), salt, 1000).getEncoded());
        assertEquals("AES/GCM/NoPadding", CryptUtil.getInstance().getCipher("AES/GCM/NoPadding").getAlgorithm());
    }
}
