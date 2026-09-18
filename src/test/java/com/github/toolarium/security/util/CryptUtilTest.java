/*
 * CryptUtilTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.util;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the {@link CryptUtil}.
 *
 * @author patrick
 */
public class CryptUtilTest {
    private static final Logger LOG = LoggerFactory.getLogger(CryptUtilTest.class);


    /**
     * Test strong encryption check
     */
    @Test
    public void testStrongEncryptionEnabled() {
        boolean enabled = CryptUtil.getInstance().isStrongEncryptionEnabled();
        LOG.debug("Strong encryption enabled: " + enabled);
        assertTrue(enabled);
    }


    /**
     * Test getCipher with mode/padding
     *
     * @throws Exception in case of error
     */
    @Test
    public void testGetCipher() throws Exception {
        Cipher cipher = CryptUtil.getInstance().getCipher("AES/ECB/PKCS5Padding");
        assertNotNull(cipher);
    }


    /**
     * Test getCipher with provider
     *
     * @throws Exception in case of error
     */
    @Test
    public void testGetCipherWithProvider() throws Exception {
        Cipher cipher = CryptUtil.getInstance().getCipher(null, "AES/ECB/PKCS5Padding");
        assertNotNull(cipher);
    }


    /**
     * Test createSecretKeySpec from passphrase
     *
     * @throws Exception in case of error
     */
    @Test
    public void testCreateSecretKeySpecFromPassphrase() throws Exception {
        SecretKeySpec key = CryptUtil.getInstance().createSecretKeySpec("my-test-passphrase");
        assertNotNull(key);
        assertNotNull(key.getEncoded());
        assertTrue(key.getEncoded().length > 0);
    }


    /**
     * Test createSecretKeySpec from bytes
     */
    @Test
    public void testCreateSecretKeySpecFromBytes() {
        byte[] keyBytes = new byte[16];
        SecretKeySpec key = CryptUtil.getInstance().createSecretKeySpec(keyBytes, "AES");
        assertNotNull(key);
    }


    /**
     * Test getMaxAllowedKeyLength
     *
     * @throws Exception in case of error
     */
    @Test
    public void testGetMaxAllowedKeyLength() throws Exception {
        int maxLength = CryptUtil.getInstance().getMaxAllowedKeyLength("AES");
        LOG.debug("Max allowed AES key length: " + maxLength);
        assertTrue(maxLength > 0);
    }


    /**
     * Test getAlgorithmMessage
     */
    @Test
    public void testGetAlgorithmMessage() {
        String msg = CryptUtil.getInstance().getAlgorithmMessage("SunJCE", "AES/GCM/NoPadding");
        assertTrue(msg.contains("SunJCE"));
        assertTrue(msg.contains("AES/GCM/NoPadding"));

        String msgNoProvider = CryptUtil.getInstance().getAlgorithmMessage(null, "AES/GCM/NoPadding");
        assertTrue(msgNoProvider.equals("AES/GCM/NoPadding"));
    }
}
