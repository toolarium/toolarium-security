/*
 * JsonSignatureUtilTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.signature;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.pki.KeyConverterFactory;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Json signature based on https://global.alipay.com/docs/ac/gr/signature#d2e38597
 * 
 * @author patrick
 */
public class JsonSignatureUtilTest {
    private static final Logger LOG = LoggerFactory.getLogger(JsonSignatureUtilTest.class);
    private static final String NL = "\n";
    private static final String BC = "BC";
    private static final String RSA = "RSA";
    private static final String EC = "EC";
    private static final String SHA256WITH_RSA = "SHA256withRSA";
    private static final String SHA256WITH_ECDSA = "SHA256withECDSA";

    private static final String TEST_JSON = "{" + NL
            + "    \"head\":{" + NL
            + "        \"version\":\"2.0.0\"," + NL
            + "        \"function\":\"alipay.intl.acquiring.agreement.payCancel\"," + NL
            + "        \"clientId\":\"211xxxxxxxxxxxxxxx044\"," + NL
            + "        \"reqTime\":\"2001-07-04T12:08:56+05:30\"," + NL
            + "        \"reqMsgId\":\"1234567asdfasdf1123fda\"," + NL
            + "        \"reserve\":\"{}\"" + NL
            + "    }," + NL
            + "    \"body\":{" + NL
            + "        \"merchantId\":\"218xxxxxxxxxxxxxxx023\"," + NL
            + "        \"acquirementId\":\"2015xxxxxxxxxxxxxxxxxxxxx747\"" + NL
            + "    }" + NL
            + "}";

    
    /**
     * Test
     * 
     * @throws GeneralSecurityException occurs, if the test contains errors.
     * @throws IOException occurs in case of an IO error
     */
    @Test
    public void testRSA2048() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        doSignAndValidate(BC, RSA, 2024, SHA256WITH_RSA, TEST_JSON);
    }

    
    /**
     * Test
     * 
     * @throws GeneralSecurityException occurs, if the test contains errors.
     * @throws IOException occurs in case of an IO error
     */
    @Test
    public void testEC256() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        doSignAndValidate(BC, EC, 256, SHA256WITH_ECDSA, TEST_JSON);
    }

    
    /**
     * Test that a tampered request body fails verification
     *
     * @throws GeneralSecurityException occurs, if the test contains errors.
     * @throws IOException occurs in case of an IO error
     */
    @Test
    public void testVerifyFailsOnTamperedContent() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        final KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(BC, RSA, 2048);
        PrivateKey privateKey = KeyConverterFactory.getInstance().getConverter(RSA).getPrivateKey(
                KeyConverterFactory.getInstance().getConverter(RSA).formatPrivateKey(keyPair.getPrivate()));
        PublicKey publicKey = KeyConverterFactory.getInstance().getConverter(RSA).getPublicKey(
                KeyConverterFactory.getInstance().getConverter(RSA).formatPublicKey(keyPair.getPublic()));

        String signed = JsonSignatureUtil.getInstance().sign(BC, SHA256WITH_RSA, privateKey, TEST_JSON);

        // tamper the request body by replacing a value
        String tampered = signed.replace("2.0.0", "9.9.9");
        boolean result = JsonSignatureUtil.getInstance().verify(BC, SHA256WITH_RSA, publicKey, tampered);
        assertFalse(result);
    }


    /**
     * Test that null JSON throws IllegalArgumentException
     */
    @Test
    public void testVerifyNullJsonThrows() {
        assertThrows(IllegalArgumentException.class, () ->
                JsonSignatureUtil.getInstance().verify(BC, SHA256WITH_RSA, null, null));
    }


    /**
     * Test that blank JSON throws IllegalArgumentException
     */
    @Test
    public void testVerifyBlankJsonThrows() {
        assertThrows(IllegalArgumentException.class, () ->
                JsonSignatureUtil.getInstance().verify(BC, SHA256WITH_RSA, null, "   "));
    }


    /**
     * Test that JSON without the expected wrapper structure throws IllegalArgumentException
     */
    @Test
    public void testVerifyMissingWrapperThrows() {
        assertThrows(IllegalArgumentException.class, () ->
                JsonSignatureUtil.getInstance().verify(BC, SHA256WITH_RSA, null, TEST_JSON));
    }


    /**
     * Test that a wrong key fails verification
     *
     * @throws GeneralSecurityException occurs, if the test contains errors.
     * @throws IOException occurs in case of an IO error
     */
    @Test
    public void testVerifyFailsWithWrongKey() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        final KeyPair signerPair = PKIUtil.getInstance().generateKeyPair(BC, RSA, 2048);
        final KeyPair otherPair  = PKIUtil.getInstance().generateKeyPair(BC, RSA, 2048);

        PrivateKey privateKey = KeyConverterFactory.getInstance().getConverter(RSA).getPrivateKey(
                KeyConverterFactory.getInstance().getConverter(RSA).formatPrivateKey(signerPair.getPrivate()));
        PublicKey wrongPublicKey = KeyConverterFactory.getInstance().getConverter(RSA).getPublicKey(
                KeyConverterFactory.getInstance().getConverter(RSA).formatPublicKey(otherPair.getPublic()));

        String signed = JsonSignatureUtil.getInstance().sign(BC, SHA256WITH_RSA, privateKey, TEST_JSON);
        boolean result = JsonSignatureUtil.getInstance().verify(BC, SHA256WITH_RSA, wrongPublicKey, signed);
        assertFalse(result);
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
     * @throws IOException occurs in case of an IO error
     */
    protected void doSignAndValidate(String provider, String keyPairAlgorithm, int keyPairSize, String signatureAlgorithm, String content) throws GeneralSecurityException, IOException {
        // create key pair
        final KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(provider, keyPairAlgorithm, keyPairSize);
        
        String privateKeyStr = KeyConverterFactory.getInstance().getConverter(keyPairAlgorithm).formatPrivateKey(keyPair.getPrivate());
        LOG.debug("Private key (do never print this outside of a test case!!!):\n" + privateKeyStr);

        String publicKeyStr = KeyConverterFactory.getInstance().getConverter(keyPairAlgorithm).formatPublicKey(keyPair.getPublic());
        LOG.debug("Public key (do never print this outside of a test case!!!):\n" + publicKeyStr);

        // ----
        
        // read key from configuration and convert to objects
        PrivateKey privateKey = KeyConverterFactory.getInstance().getConverter(keyPairAlgorithm).getPrivateKey(privateKeyStr);
        
        // sign JSON
        String jsonResponse = JsonSignatureUtil.getInstance().sign(provider, signatureAlgorithm, privateKey, content);

        // ----
        
        // verify:
        
        // read key from configuration and convert to objects
        PublicKey publicKey = KeyConverterFactory.getInstance().getConverter(keyPairAlgorithm).getPublicKey(publicKeyStr);
        
        // decode signature and compare
        boolean result = JsonSignatureUtil.getInstance().verify(provider, signatureAlgorithm, publicKey, jsonResponse);
        assertTrue(result);
    }
}
