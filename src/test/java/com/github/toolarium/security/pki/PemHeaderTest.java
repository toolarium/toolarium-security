/*
 * PemHeaderTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.configuration.PKIConfigurationUtil;
import com.github.toolarium.security.pki.impl.AbstractKeyConverter;
import com.github.toolarium.security.pki.impl.ECKeyConverter;
import com.github.toolarium.security.pki.impl.RSAKeyConverter;
import com.github.toolarium.security.pki.impl.rsa.RSAPrivateKeyPKCS8;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;


/**
 * Test the PEM headers of the key converters: standard headers by default, legacy headers with the system property,
 * reading of both variants, the key type detection and PKCS#1 RSA keys.
 *
 * @author patrick
 */
public class PemHeaderTest {
    private static final String RSA = "RSA";
    private static final String EC = "EC";
    private static final String NL = "\n";


    /**
     * Constructor for PemHeaderTest
     */
    public PemHeaderTest() {
        // NOP
    }


    /**
     * Remove the system property.
     */
    @AfterEach
    public void tearDown() {
        System.clearProperty(AbstractKeyConverter.LEGACY_PEM_HEADERS_PROPERTY);
    }


    /**
     * By default the standard headers are written and can be read again, also by the generic reader.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testStandardHeaders() throws Exception {
        IKeyConverter converter = KeyConverterFactory.getInstance().getConverter(RSA);
        KeyPair keyPair = converter.generateKeyPair();
        String privateKeyPem = converter.formatPrivateKey(keyPair.getPrivate());
        String publicKeyPem = converter.formatPublicKey(keyPair.getPublic());
        assertTrue(privateKeyPem.startsWith(AbstractKeyConverter.PRIVATE_KEY_START), privateKeyPem);
        assertTrue(publicKeyPem.startsWith(AbstractKeyConverter.PUBLIC_KEY_START), publicKeyPem);

        assertArrayEquals(keyPair.getPrivate().getEncoded(), converter.getPrivateKey(privateKeyPem).getEncoded());
        assertArrayEquals(keyPair.getPublic().getEncoded(), converter.getPublicKey(publicKeyPem).getEncoded());
        assertArrayEquals(keyPair.getPrivate().getEncoded(), PKIConfigurationUtil.getInstance().getPrivateKey(privateKeyPem).getEncoded());
        assertArrayEquals(keyPair.getPublic().getEncoded(), PKIConfigurationUtil.getInstance().getPublicKey(publicKeyPem).getEncoded());
    }


    /**
     * With the system property the legacy headers are written, and they can be read as before.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testLegacyHeaders() throws Exception {
        System.setProperty(AbstractKeyConverter.LEGACY_PEM_HEADERS_PROPERTY, "true");
        IKeyConverter converter = KeyConverterFactory.getInstance().getConverter(RSA);
        KeyPair keyPair = converter.generateKeyPair();
        String privateKeyPem = converter.formatPrivateKey(keyPair.getPrivate());
        String publicKeyPem = converter.formatPublicKey(keyPair.getPublic());
        assertTrue(privateKeyPem.startsWith(RSAKeyConverter.PRIVATE_RSA_KEY_START), privateKeyPem);
        assertTrue(publicKeyPem.startsWith(RSAKeyConverter.PUBLIC_RSA_KEY_START), publicKeyPem);

        assertArrayEquals(keyPair.getPrivate().getEncoded(), converter.getPrivateKey(privateKeyPem).getEncoded());
        assertArrayEquals(keyPair.getPublic().getEncoded(), converter.getPublicKey(publicKeyPem).getEncoded());
        assertArrayEquals(keyPair.getPrivate().getEncoded(), PKIConfigurationUtil.getInstance().getPrivateKey(privateKeyPem).getEncoded());
    }


    /**
     * The key type of a generic PEM (no type in the header) is taken from the algorithm identifier inside the key.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testKeyTypeDetection() throws Exception {
        IKeyConverter converter = KeyConverterFactory.getInstance().getConverter(EC);
        KeyPair keyPair = converter.generateKeyPair();
        String privateKeyPem = converter.formatPrivateKey(keyPair.getPrivate());
        String publicKeyPem = converter.formatPublicKey(keyPair.getPublic());
        assertTrue(privateKeyPem.startsWith(AbstractKeyConverter.PRIVATE_KEY_START), privateKeyPem);
        assertEquals(EC, PKIConfigurationUtil.getInstance().getPrivateKey(privateKeyPem).getAlgorithm());
        assertEquals(EC, PKIConfigurationUtil.getInstance().getPublicKey(publicKeyPem).getAlgorithm());

        // the old EC header is still accepted
        String legacyPem = privateKeyPem.replace(AbstractKeyConverter.PRIVATE_KEY_START, ECKeyConverter.PRIVATE_EC_KEY_START)
                .replace(AbstractKeyConverter.PRIVATE_KEY_END, ECKeyConverter.PRIVATE_EC_KEY_END);
        assertArrayEquals(keyPair.getPrivate().getEncoded(), converter.getPrivateKey(legacyPem).getEncoded());
    }


    /**
     * A PKCS#1 RSA private key (e.g. openssl genrsa -traditional) is converted into a usable key.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testPkcs1PrivateKey() throws Exception {
        IKeyConverter converter = KeyConverterFactory.getInstance().getConverter(RSA);
        KeyPair keyPair = converter.generateKeyPair();
        byte[] pkcs1 = PrivateKeyInfo.getInstance(keyPair.getPrivate().getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded();
        String pem = RSAKeyConverter.PRIVATE_RSA_KEY_START + NL + Base64.getMimeEncoder(64, NL.getBytes()).encodeToString(pkcs1) + NL + RSAKeyConverter.PRIVATE_RSA_KEY_END + NL;

        PrivateKey privateKey = converter.getPrivateKey(pem);
        assertArrayEquals(keyPair.getPrivate().getEncoded(), privateKey.getEncoded());

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(new byte[] {1, 2, 3});
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(new byte[] {1, 2, 3});
        assertTrue(verifier.verify(signature));
    }


    /**
     * A key which is neither PKCS#8 nor PKCS#1 is rejected when it is loaded.
     */
    @Test
    public void testInvalidRsaPrivateKey() {
        String pem = RSAKeyConverter.PRIVATE_RSA_KEY_START + NL + Base64.getEncoder().encodeToString(new byte[] {0x30, 0x03, 0x02, 0x01, 0x00}) + NL + RSAKeyConverter.PRIVATE_RSA_KEY_END;
        assertThrows(GeneralSecurityException.class, () -> KeyConverterFactory.getInstance().getConverter(RSA).getPrivateKey(pem));
    }


    /**
     * A destroyed key can not be used anymore.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testDestroyPrivateKey() throws Exception {
        KeyPair keyPair = KeyConverterFactory.getInstance().getConverter(RSA).generateKeyPair();
        RSAPrivateKeyPKCS8 privateKey = new RSAPrivateKeyPKCS8(keyPair.getPrivate().getEncoded());
        assertTrue(privateKey.getEncoded().length > 0);
        privateKey.destroy();
        assertTrue(privateKey.isDestroyed());
        assertThrows(IllegalStateException.class, () -> privateKey.getEncoded());
    }
}
