/*
 * PKIConfigurationFindingsTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.configuration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.toolarium.security.pki.util.PKIUtil;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Base64;
import org.junit.jupiter.api.Test;


/**
 * Test the fix of the finding N34 of the {@link PKIConfigurationUtil}: a malformed PEM header never puts the key
 * body into the exception message.
 *
 * @author patrick
 */
public class PKIConfigurationFindingsTest {
    private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";


    /**
     * Constructor for PKIConfigurationFindingsTest
     */
    public PKIConfigurationFindingsTest() {
        // NOP
    }


    /**
     * A private key with a malformed header (4 dashes) is rejected without the key body in the message.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testMalformedPrivateKeyHeader() throws GeneralSecurityException {
        KeyPair keyPair = PKIUtil.getInstance().generateKeyPair("RSA", 2048);
        String body = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        assertNotNull(PKIConfigurationUtil.getInstance().getPrivateKey("-----BEGIN PRIVATE KEY-----\n" + body + "\n" + END_PRIVATE_KEY));

        assertNoKeyBody(body, () -> PKIConfigurationUtil.getInstance().getPrivateKey("-----BEGIN PRIVATE KEY----\n" + body + "\n" + END_PRIVATE_KEY));
        assertNoKeyBody(body, () -> PKIConfigurationUtil.getInstance().getPrivateKey("-----BEGIN PRIVATE KEY---- " + body + " " + END_PRIVATE_KEY));
        assertNoKeyBody(body, () -> PKIConfigurationUtil.getInstance().getPrivateKey("-----BEGIN RSA\nPRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----"));
    }


    /**
     * A public key with a malformed header (4 dashes) is rejected without the key body in the message.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testMalformedPublicKeyHeader() throws GeneralSecurityException {
        KeyPair keyPair = PKIUtil.getInstance().generateKeyPair("RSA", 2048);
        String body = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        assertNotNull(PKIConfigurationUtil.getInstance().getPublicKey("-----BEGIN PUBLIC KEY-----\n" + body + "\n" + END_PUBLIC_KEY));

        assertNoKeyBody(body, () -> PKIConfigurationUtil.getInstance().getPublicKey("-----BEGIN PUBLIC KEY----\n" + body + "\n" + END_PUBLIC_KEY));
        assertNoKeyBody(body, () -> PKIConfigurationUtil.getInstance().getPublicKey("-----BEGIN PUBLIC KEY---- " + body + " " + END_PUBLIC_KEY));
    }


    /**
     * Assert that the call fails and the message contains no part of the key body.
     *
     * @param body the key body
     * @param call the call
     */
    private void assertNoKeyBody(String body, KeyCall call) {
        GeneralSecurityException e = assertThrows(GeneralSecurityException.class, call::execute);
        String message = String.valueOf(e.getMessage());
        assertFalse(message.contains(body.substring(0, 16)));
        assertFalse(message.contains(body.substring(body.length() - 16)));
    }


    /**
     * A call which reads a key.
     */
    @FunctionalInterface
    private interface KeyCall {
        /**
         * Execute the call.
         *
         * @throws GeneralSecurityException in case of error
         */
        void execute() throws GeneralSecurityException;
    }
}
