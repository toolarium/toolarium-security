/*
 * CryptionUtilTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.cryption.util;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.common.security.ISecuredSecretValue;
import com.github.toolarium.common.security.SecuredValueFactory;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the {@link CryptionUtil}.
 *
 * @author patrick
 */
public class CryptionUtilTest {
    private static final Logger LOG = LoggerFactory.getLogger(CryptionUtilTest.class);


    /**
     * Constructor for CryptionUtilTest
     */
    public CryptionUtilTest() {
        // NOP
    }


    /**
     * Test strong encryption check
     */
    @Test
    public void testStrongEncryptionEnabled() {
        boolean enabled = CryptionUtil.getInstance().isStrongEncryptionEnabled();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Strong encryption enabled: {}", enabled);
        }
        assertTrue(enabled);
    }


    /**
     * Test getCipher with mode/padding
     *
     * @throws Exception in case of error
     */
    @Test
    public void testGetCipher() throws Exception {
        Cipher cipher = CryptionUtil.getInstance().getCipher("AES/ECB/PKCS5Padding");
        assertNotNull(cipher);
    }


    /**
     * Test getCipher with provider
     *
     * @throws Exception in case of error
     */
    @Test
    public void testGetCipherWithProvider() throws Exception {
        Cipher cipher = CryptionUtil.getInstance().getCipher(null, "AES/ECB/PKCS5Padding");
        assertNotNull(cipher);
    }


    /**
     * Test createSecretKeySpec from passphrase (fixed-salt overload)
     *
     * @throws Exception in case of error
     */
    @Test
    public void testCreateSecretKeySpecFromPassphrase() throws Exception {
        SecretKeySpec key = CryptionUtil.getInstance().createSecretKeySpec("my-test-passphrase".toCharArray());
        assertNotNull(key);
        assertNotNull(key.getEncoded());
        assertTrue(key.getEncoded().length > 0);
    }


    /**
     * Test createSecretKeySpec from passphrase with explicit salt and iterations
     *
     * @throws Exception in case of error
     */
    @Test
    public void testCreateSecretKeySpecFromPassphraseWithSalt() throws Exception {
        byte[] salt = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        SecretKeySpec key = CryptionUtil.getInstance().createSecretKeySpec("my-test-passphrase".toCharArray(), salt, 10_000);
        assertNotNull(key);
        assertNotNull(key.getEncoded());
        assertTrue(key.getEncoded().length > 0);
    }


    /**
     * Test createSecretKeySpec from ISecuredSecretValue passphrase (fixed-salt overload)
     *
     * @throws Exception in case of error
     */
    @Test
    public void testCreateSecretKeySpecFromSecuredValue() throws Exception {
        ISecuredSecretValue passphrase = SecuredValueFactory.getInstance().createSecret("my-test-passphrase".toCharArray(), "test");
        SecretKeySpec key = CryptionUtil.getInstance().createSecretKeySpec(passphrase);
        assertNotNull(key);
        assertNotNull(key.getEncoded());
        assertTrue(key.getEncoded().length > 0);
    }


    /**
     * Test createSecretKeySpec from ISecuredSecretValue passphrase with explicit salt and iterations
     *
     * @throws Exception in case of error
     */
    @Test
    public void testCreateSecretKeySpecFromSecuredValueWithSalt() throws Exception {
        ISecuredSecretValue passphrase = SecuredValueFactory.getInstance().createSecret("my-test-passphrase".toCharArray(), "test");
        byte[] salt = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        SecretKeySpec key = CryptionUtil.getInstance().createSecretKeySpec(passphrase, salt, 10_000);
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
        SecretKeySpec key = CryptionUtil.getInstance().createSecretKeySpec(keyBytes, "AES");
        assertNotNull(key);
    }


    /**
     * Test getMaxAllowedKeyLength
     *
     * @throws Exception in case of error
     */
    @Test
    public void testGetMaxAllowedKeyLength() throws Exception {
        int maxLength = CryptionUtil.getInstance().getMaxAllowedKeyLength("AES");
        if (LOG.isDebugEnabled()) {
            LOG.debug("Max allowed AES key length: {}", maxLength);
        }
        assertTrue(maxLength > 0);
    }


    /**
     * Test getAlgorithmMessage
     */
    @Test
    public void testGetAlgorithmMessage() {
        String msg = CryptionUtil.getInstance().getAlgorithmMessage("SunJCE", "AES/GCM/NoPadding");
        assertTrue(msg.contains("SunJCE"));
        assertTrue(msg.contains("AES/GCM/NoPadding"));

        String msgNoProvider = CryptionUtil.getInstance().getAlgorithmMessage(null, "AES/GCM/NoPadding");
        assertTrue(msgNoProvider.equals("AES/GCM/NoPadding"));
    }
}
