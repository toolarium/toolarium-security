/*
 * KeyConverterTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.github.toolarium.security.certificate.util.PKIUtilTest;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the {@link IKeyConverter}.
 * 
 * @author patrick
 */
public class KeyConverterTest {
    
    /** the RSA certificate test file */
    public static final String TEST_RSA_KEYFILE = "testprivatekey.pem";

    /** Defines the resource */
    public static final String TEST_RESOURCE_PATH = "src/test/resources";
    
    private static final String TEST_RSA_PRIVATE_KEY = "MIICXQIBAAKBgQDLj0AFhZuP5p4k5YZgekZNhhnGTMVB/EBTGOocnEJD/4PfS7hfTOu6OJ9zWy4COvpmb8sBdJnRioF4LIQ+jdifuMt+sXAQ5xI4B/NIVaV8Fx5ZwiJEVpXhL2GCr5LQUbC"
            + "pYG04JSiCHeyr4JdbcY65ulMRMa9pQdqkhzH4pzfn2wIDAQABAoGBALmUK6XdHOmgMmUo681hLF7Y9v6WVu/FbU9U03qp6q/bbvpQKhKYKgBoRtYANn3KDyb8nHMDPoiOYWKSEy6EWwwCIOkUTxLxAnYHe7uVbavrFq0EWmpNqca1aELsqqeRJSj"
            + "in4uqo+mjuYatAgjcxezrB+NcyoSxt+P1XAsMF7whAkEA6vKK3EnAKPbsXr2k77ffvlUuibB8Y4mCD/WxxZ/E/sHVz6r4PLZLzQahfQlcvRgO6RmkX2fMSKFF4VJqKItaDQJBAN3Ms6Slie8VNyeiP/jNDwSs471Fe8Ap0G4KYaVRySKmdVaN2NO"
            + "opLDCNeSfbx9YaQj5DyfhFVq5Lr10vy9lV4cCQQDKTJlAYMhy/Vo9oXGZb2vaSSJPMIWKd2ZkM5wknBNVgLWHoKEqNZVDLohyT1NpBoQgNhIQjCGcEDFJeFssGgEpAkAc+ukiAyshnQEG4bFAHfLvZnOfQFvqAMymBB88DZKdP2indYM2LJvQKKA"
            + "IDjjjvJaEwJ4VVNiIcRfFU2LDm5czAkAM5JOBzd6VnBLjXYnwooCdTXrP4DOnCAry+vUBcsSR/Rj3sGCqF077gIQfibtZIVMbcJ7w9y9/SBddFWh9xtDV";
    private static final Logger LOG = LoggerFactory.getLogger(PKIUtilTest.class);

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testFormatRSAKey() throws Exception {
        KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(null, "RSA", 2048);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PKIUtil.getInstance().processPrivateKeyInfo(LOG::debug, null, privateKey);
        PKIUtil.getInstance().processPublicKeyInfo(LOG::debug, null, publicKey);

        String privateKeyString = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).formatPrivateKey(privateKey);
        LOG.debug("Private key:" + privateKeyString);
        String publicKeyString = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).formatPublicKey(publicKey);
        LOG.debug("Public key:" + publicKeyString);

        PrivateKey privateKey2 = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).getPrivateKey(privateKeyString);
        PublicKey publicKey2 = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).getPublicKey(publicKeyString);

        assertEquals(privateKey, privateKey2);
        assertEquals(publicKey, publicKey2);
    }

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testFormatDSAKey() throws Exception {
        KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(null, "DSA", 2048);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PKIUtil.getInstance().processPrivateKeyInfo(LOG::debug, null, privateKey);
        PKIUtil.getInstance().processPublicKeyInfo(LOG::debug, null, publicKey);

        String privateKeyString = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.DSA).formatPrivateKey(privateKey);
        LOG.debug("Private key:" + privateKeyString);
        String publicKeyString = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.DSA).formatPublicKey(publicKey);
        LOG.debug("Public key:" + publicKeyString);

        PrivateKey privateKey2 = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.DSA).getPrivateKey(privateKeyString);
        PublicKey publicKey2 = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.DSA).getPublicKey(publicKeyString);

        PKIUtil.getInstance().processPrivateKeyInfo(LOG::debug, null, privateKey);

        assertEquals(privateKey, privateKey2);
        assertEquals(publicKey, publicKey2);
    }

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testFormatECKey() throws Exception {
        KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(null, "EC", 256);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PKIUtil.getInstance().processPrivateKeyInfo(LOG::debug, null, privateKey);
        PKIUtil.getInstance().processPublicKeyInfo(LOG::debug, null, publicKey);

        String privateKeyString = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.EC).formatPrivateKey(privateKey);
        LOG.debug("Private key:" + privateKeyString);
        String publicKeyString = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.EC).formatPublicKey(publicKey);
        LOG.debug("Public key:" + publicKeyString);

        PrivateKey privateKey2 = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.EC).getPrivateKey(privateKeyString);
        PublicKey publicKey2 = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.EC).getPublicKey(publicKeyString);

        assertEquals(privateKey, privateKey2);
        assertEquals(publicKey, publicKey2);
    }

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testNormalizePrivateKeyFromBuffer() throws Exception {
        String data = TEST_RSA_PRIVATE_KEY;
        String wellFormed = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).formatPKCS8(data);
        String normalizedForm = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).normalizePKCS8(wellFormed);
        assertEquals(data, normalizedForm);
        PrivateKey key = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).getPrivateKey(normalizedForm);
        assertNotNull(key);
    }


    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testReadPrivateKeyFromFile() throws Exception {
        PrivateKey key = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).getPrivateKey(Paths.get(TEST_RESOURCE_PATH, TEST_RSA_KEYFILE).toFile());

        assertNotNull(key);
        assertEquals("RSA", key.getAlgorithm());
        assertEquals("PKCS#8", key.getFormat());
        assertNotNull(key.getEncoded());
    }

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testReadPrivateKeyFromBuffer() throws Exception {
        PrivateKey key = KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).getPrivateKey(TEST_RSA_PRIVATE_KEY);
        assertNotNull(key);
    }
}
