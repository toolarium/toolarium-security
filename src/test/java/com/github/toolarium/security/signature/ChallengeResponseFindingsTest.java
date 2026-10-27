/*
 * ChallengeResponseFindingsTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.signature;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.pki.util.PKIUtil;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;


/**
 * Test the fix of the finding N52 of the {@link ChallengeResponseUtil}: null parameters and malformed Base64 give a
 * {@link GeneralSecurityException}.
 *
 * @author patrick
 */
public class ChallengeResponseFindingsTest {
    private static final String ALGORITHM = "SHA256withRSA";


    /**
     * Constructor for ChallengeResponseFindingsTest
     */
    public ChallengeResponseFindingsTest() {
        // NOP
    }


    /**
     * Null parameters and malformed Base64 are reported as {@link GeneralSecurityException}.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testInvalidParameters() throws GeneralSecurityException {
        KeyPair keyPair = PKIUtil.getInstance().generateKeyPair("RSA", 2048);
        ChallengeResponseUtil util = ChallengeResponseUtil.getInstance();
        byte[] challenge = util.getChallenge(32);
        byte[] response = util.generateResponse(ALGORITHM, keyPair.getPrivate(), challenge);
        assertTrue(util.checkResponse(ALGORITHM, keyPair.getPublic(), challenge, response));

        assertThrows(GeneralSecurityException.class, () -> util.checkResponse(ALGORITHM, keyPair.getPublic(), null, response));
        assertThrows(GeneralSecurityException.class, () -> util.checkResponse(ALGORITHM, keyPair.getPublic(), challenge, null));

        byte[] malformed = "not*valid*base64!".getBytes(StandardCharsets.US_ASCII);
        assertThrows(GeneralSecurityException.class, () -> util.checkResponse(ALGORITHM, keyPair.getPublic(), challenge, malformed));
        assertThrows(GeneralSecurityException.class, () -> util.checkResponse(ALGORITHM, keyPair.getPublic(), malformed, response));
    }
}
