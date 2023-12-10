/*
 * ChallengeResponseUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.util;

import com.github.toolarium.common.util.RandomGenerator;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Base64.Decoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * <p>This class implements method which can be used for a challenge/response
 * protocol. The challenge is a base64 coded random number which can be created
 * by the method <code>getChallenge</code>.</p>
 * <p>The method <code>checkResponse</code> checks a given response which should
 * be signed with a <code>PrivateKey</code>.</p>
 * 
 * @author patrick
 */
public final class ChallengeResponseUtil {
    private static final Logger LOG = LoggerFactory.getLogger(ChallengeResponseUtil.class);
    

    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final ChallengeResponseUtil INSTANCE = new ChallengeResponseUtil();
    }

    
    /**
     * Constructor
     */
    private ChallengeResponseUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static ChallengeResponseUtil getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Returns a random number as base64 encoded string
     * 
     * @param size the size in byte
     * @return a random number of the given size with base64 encoded
     * @throws GeneralSecurityException in case of error
     */
    public byte[] getChallenge(int size) throws GeneralSecurityException {
        if (size <= 0) {
            throw new GeneralSecurityException("Invalid size!");
        }
        
        if (LOG.isInfoEnabled()) {
            LOG.info("Generating challenge (" + size + " bytes)...");
        }

        byte[] challange = RandomGenerator.getInstance().nextBytes(size);
        return Base64.getEncoder().encode(challange);
    }

    
    /**
     * Checks the response given against the challenge verified with the certificate's public key
     * 
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param publicKey the public key
     * @param challenge the base64 encoded challenge
     * @param response the base64 encoded response
     * @return true if the verification of the response is identical.
     * @throws GeneralSecurityException in case of error
     */
    public boolean checkResponse(String algorithm, PublicKey publicKey, byte[] challenge, byte[] response) throws GeneralSecurityException {
        return checkResponse(null, algorithm, publicKey, challenge, response);
    }

    
    /**
     * Checks the response given against the challenge verified with the certificate's public key
     * 
     * @param provider the provider
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param publicKey the public key
     * @param challenge the base64 encoded challenge
     * @param response the base64 encoded response
     * @return true if the verification of the response is identical.
     * @throws GeneralSecurityException in case of error
     */
    public boolean checkResponse(String provider, String algorithm, PublicKey publicKey, byte[] challenge, byte[] response) throws GeneralSecurityException {
        if (LOG.isInfoEnabled()) {
            LOG.info("Checking response...");
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("  Challenge: " + new String(challenge));
        }

        // check parameters
        checkParameter(algorithm);
        checkParameter(publicKey);
        checkParameter(challenge);
        checkParameter(response);

        Decoder decoder = Base64.getDecoder();
        return SignatureUtil.getInstance().verify(provider, algorithm, publicKey, decoder.decode(challenge), decoder.decode(response));
    }


    /**
     * Generates a response based on the given challenge and private key using the specified algorithm and provider
     * 
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param challenge the base64 encoded challenge
     * @param privateKey the private key as string
     * @return the signed response
     * @throws GeneralSecurityException in case of error
     */
    public byte[] generateResponse(String algorithm, PrivateKey privateKey, byte[] challenge) throws GeneralSecurityException {
        return generateResponse(null, algorithm, privateKey, challenge);
    }

    
    /**
     * Generates a response based on the given challenge and private key using the specified algorithm and provider
     * 
     * @param provider the provider
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param privateKey the private key
     * @param challenge the base64 encoded challenge
     * @return the signed response
     * @throws GeneralSecurityException in case of error
     */
    public byte[] generateResponse(String provider, String algorithm, PrivateKey privateKey, byte[] challenge) throws GeneralSecurityException {
        if (LOG.isInfoEnabled()) {
            LOG.info("Generate response...");
        }

        // check parameters
        checkParameter(algorithm);
        checkParameter(privateKey);
        checkParameter(challenge);

        final byte[] result = SignatureUtil.getInstance().sign(provider, algorithm, privateKey, Base64.getDecoder().decode(challenge));
        return Base64.getEncoder().encode(result);
    }

    
    /**
     * Checks a given object
     * 
     * @param obj the object to check
     * @throws GeneralSecurityException in case of error
     */
    private void checkParameter(Object obj) throws GeneralSecurityException {
        if (obj == null) {
            throw new GeneralSecurityException("Invalid parameter (null)!");
        }
    }

    
    /**
     * Checks a given string
     * 
     * @param d the object to check
     * @throws GeneralSecurityException in case of error
     */
    private void checkParameter(String d) throws GeneralSecurityException {
        if (d == null) {
            throw new GeneralSecurityException("Invalid parameter (null)!");
        }

        if (d.length() == 0) {
            throw new GeneralSecurityException("Invalid empty parameter!");
        }
    }
}
