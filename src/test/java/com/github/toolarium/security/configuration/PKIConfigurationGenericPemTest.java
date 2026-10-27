/*
 * PKIConfigurationGenericPemTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.configuration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.toolarium.security.pki.util.PKIUtil;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Base64;
import org.junit.jupiter.api.Test;


/**
 * Test the generic PEM headers (-----BEGIN PRIVATE KEY----- / -----BEGIN PUBLIC KEY-----) of the {@link PKIConfigurationUtil} (N26).
 *
 * @author patrick
 */
public class PKIConfigurationGenericPemTest {

    /**
     * Constructor for PKIConfigurationGenericPemTest
     */
    public PKIConfigurationGenericPemTest() {
        // NOP
    }


    /**
     * Test generic RSA PEM keys
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testGenericRSAKeys() throws GeneralSecurityException {
        assertGenericKeys(PKIUtil.getInstance().generateKeyPair("RSA", 2048), null);
    }


    /**
     * Test generic EC PEM keys (key type detected)
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testGenericECKeys() throws GeneralSecurityException {
        assertGenericKeys(PKIUtil.getInstance().generateKeyPair("EC", 256), null);
    }


    /**
     * Test generic EC PEM keys with explicit key type
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testGenericECKeysWithKeyType() throws GeneralSecurityException {
        assertGenericKeys(PKIUtil.getInstance().generateKeyPair("EC", 256), "EC");
    }


    /**
     * Unsupported or encrypted keys are reported as {@link GeneralSecurityException}
     */
    @Test
    public void testUnsupportedKeys() {
        assertThrows(GeneralSecurityException.class, () -> PKIConfigurationUtil.getInstance().getPrivateKey("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"));
        assertThrows(GeneralSecurityException.class, () -> PKIConfigurationUtil.getInstance().getPrivateKey("-----BEGIN FOO PRIVATE KEY-----\nAAAA\n-----END FOO PRIVATE KEY-----"));
        assertThrows(GeneralSecurityException.class, () -> PKIConfigurationUtil.getInstance().getPrivateKey("-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----"));
        assertThrows(GeneralSecurityException.class, () -> PKIConfigurationUtil.getInstance().getPublicKey("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"));
    }


    /**
     * Assert the generic PEM keys
     *
     * @param keyPair the key pair
     * @param keyType the key type or null
     * @throws GeneralSecurityException in case of error
     */
    private void assertGenericKeys(KeyPair keyPair, String keyType) throws GeneralSecurityException {
        String privateKeyPem = toPem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
        String publicKeyPem = toPem("PUBLIC KEY", keyPair.getPublic().getEncoded());
        assertEquals(keyPair.getPrivate(), PKIConfigurationUtil.getInstance().getPrivateKey(privateKeyPem, keyType));
        assertEquals(keyPair.getPublic(), PKIConfigurationUtil.getInstance().getPublicKey(publicKeyPem, keyType));
    }


    /**
     * Create a PEM string
     *
     * @param type the type
     * @param content the content
     * @return the PEM string
     */
    private String toPem(String type, byte[] content) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(content) + "\n-----END " + type + "-----\n";
    }
}
