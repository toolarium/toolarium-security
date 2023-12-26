/*
 * SignatureUtilTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.signature;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.pki.util.PKIUtil;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the signature util.
 *  
 * @author patrick
 */
public class SignatureUtilTest {
    private static final Logger LOG = LoggerFactory.getLogger(SignatureUtilTest.class);
    private static final String BC = "BC";
    private static final String RSA = "RSA";
    private static final String EC = "EC";
    private static final String SHA256WITH_RSA = "SHA256withRSA";
    private static final String SHA256WITH_ECDSA = "SHA256withECDSA";

    
    /**
     * Test
     * 
     * @throws GeneralSecurityException occurs, if the test contains errors.
     */
    @Test
    public void testRSA2048() throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleProvider());
        String content = "1234565467084870t8re09mgfdjkgfdjsdkljkldjklsdjfkl jfklsdj klfsdj klfj sdklfj sdkljfklsdj fklsdklsfd";
        doSignAndValidate(BC, RSA, 2024, SHA256WITH_RSA, content);
    }

    
    /**
     * Test
     * 
     * @throws GeneralSecurityException occurs, if the test contains errors.
     */
    @Test
    public void testEC256() throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleProvider());
        String content = "12345";
        doSignAndValidate(BC, EC, 256, SHA256WITH_ECDSA, content);
    }

    
    /**
     * Sign and validate
     *
     * @param provider the provider
     * @param keyPairAlgorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param keyPairSize the size of the key
     * @param signatureAlgorithm the signature algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param content the content
     * @throws GeneralSecurityException occurs, if the test contains errors.
     */
    protected void doSignAndValidate(String provider, String keyPairAlgorithm, int keyPairSize, String signatureAlgorithm, String content) throws GeneralSecurityException {
        // create key pair
        final KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(provider, keyPairAlgorithm, keyPairSize);
        
        // raw content to sign and test
        final byte[] rawContent = content.getBytes(StandardCharsets.UTF_8);

        // create signature
        final byte[] rawSignature = SignatureUtil.getInstance().sign(provider, signatureAlgorithm, keyPair.getPrivate(), rawContent);
        final String signature = new String(Base64.getEncoder().encode(rawSignature));
        LOG.debug("Signature: " + signature);

        // decode signature and compare
        final byte[] sigantureToVerify = Base64.getDecoder().decode(signature.getBytes());
        boolean result = SignatureUtil.getInstance().verify(provider, signatureAlgorithm, keyPair.getPublic(), rawContent, sigantureToVerify);
        assertTrue(result);
    }
}
