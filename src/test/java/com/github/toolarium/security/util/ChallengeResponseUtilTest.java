/*
 * ChallengeResponseUtilTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.certificate.util.PKIUtil;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;


/**
 * Test the {@link ChallengeResponseUtil}.
 * 
 * @author patrick
 */
public class ChallengeResponseUtilTest {
    private static final String RSA = "RSA";
    private static final String SHA1WITH_RSA = "SHA1withRSA";
    private static final String DSA = "DSA";
    private static final String SHA1WITH_DSA = "SHA1withDSA";


    /**
     * Test getChallenge.
     *
     * @throws GeneralSecurityException occurs, if the test contains errors.
     */
    @Test
    public void testGetChallenge() throws GeneralSecurityException {
        byte[] challenge = ChallengeResponseUtil.getInstance().getChallenge(32);
        assertNotNull(challenge);
        assertEquals(challenge.length, 44);
    }

    
    /**
     * Test
     * 
     * @throws GeneralSecurityException occurs, if the test contains errors.
     */
    @Test
    public void testDSA512() throws GeneralSecurityException {
        doChallengeResponse(null, DSA, 512, SHA1WITH_DSA, 32);
        doChallengeResponse(null, DSA, 512, SHA1WITH_DSA, 64);
        doChallengeResponse(null, DSA, 512, SHA1WITH_DSA, 128);
        doChallengeResponse(null, DSA, 512, SHA1WITH_DSA, 256);
    }

    
    /**
     * Test
     * 
     * @throws GeneralSecurityException occurs, if the test contains errors.
     */
    @Test
    public void testDSA1024() throws GeneralSecurityException {
        doChallengeResponse(null, DSA, 1024, SHA1WITH_DSA, 32);
        doChallengeResponse(null, DSA, 1024, SHA1WITH_DSA, 64);
        doChallengeResponse(null, DSA, 1024, SHA1WITH_DSA, 128);
        doChallengeResponse(null, DSA, 1024, SHA1WITH_DSA, 256);
    }


    /**
     * Test
     * 
     * @throws GeneralSecurityException occurs, if the test contains errors.
     */
    @Test
    public void testRSA512() throws GeneralSecurityException {
        doChallengeResponse(null, RSA, 512, SHA1WITH_RSA, 32);
        doChallengeResponse(null, RSA, 512, SHA1WITH_RSA, 64);
        doChallengeResponse(null, RSA, 512, SHA1WITH_RSA, 128);
        doChallengeResponse(null, RSA, 512, SHA1WITH_RSA, 256);
    }

    
    /**
     * Test
     * 
     * @throws GeneralSecurityException occurs, if the test contains errors.
     */
    @Test
    public void testRSA1024() throws GeneralSecurityException {
        doChallengeResponse(null, RSA, 1024, SHA1WITH_RSA, 32);
        doChallengeResponse(null, RSA, 1024, SHA1WITH_RSA, 64);
        doChallengeResponse(null, RSA, 1024, SHA1WITH_RSA, 128);
        doChallengeResponse(null, RSA, 1024, SHA1WITH_RSA, 256);
    }

    
    /**
     * Test the challenge response
     *
     * @param provider the provider
     * @param genAlgorithm the algorithm
     * @param size the size
     * @param algorithm the algorithm
     * @param challengeLength the length of the challenge
     * @throws GeneralSecurityException occurs, if the test contains errors.
     */
    protected void doChallengeResponse(String provider, String genAlgorithm, int size, String algorithm, int challengeLength) throws GeneralSecurityException {
        KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(provider, genAlgorithm, size);

        // generate challenge
        byte[] challenge = ChallengeResponseUtil.getInstance().getChallenge(challengeLength);

        // generate response of the given challenge
        byte[] response = ChallengeResponseUtil.getInstance().generateResponse(provider, algorithm, keyPair.getPrivate(), challenge);

        // verify the response and the challenge
        assertTrue(ChallengeResponseUtil.getInstance().checkResponse(provider, algorithm, keyPair.getPublic(), challenge, response));
    }
}
