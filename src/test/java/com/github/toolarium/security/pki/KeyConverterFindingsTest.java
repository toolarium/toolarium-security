/*
 * KeyConverterFindingsTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.pki.impl.DSAKeyConverter;
import com.github.toolarium.security.pki.impl.ECKeyConverter;
import com.github.toolarium.security.pki.impl.RSAKeyConverter;
import com.github.toolarium.security.pki.impl.rsa.RSAPrivateKeyPKCS8;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;


/**
 * Test the fixes of the key converter findings N44, N85, N86, N87, N88, N95 and N99.
 *
 * @author patrick
 */
public class KeyConverterFindingsTest {
    private static final String RSA = "RSA";
    private static final String EC = "EC";
    private static final String INVALID_BASE64 = "!!!not base64!!!";
    private static final String NOT_EXISTING_PROVIDER = "NOT-EXISTING-PROVIDER";
    private static final int THREADS = 8;


    /**
     * N44: a key created from the encoded bytes returns the key specification, the modulus and the private exponent.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testKeySpecFromEncodedKey() throws Exception {
        KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(null, RSA, 2048);
        RSAPrivateCrtKey original = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPrivateKeyPKCS8 privateKey = new RSAPrivateKeyPKCS8(original.getEncoded());

        assertNotNull(privateKey.getKeySpec());
        assertEquals(original.getModulus(), privateKey.getModulus());
        assertEquals(original.getPrivateExponent(), privateKey.getPrivateExponent());
        assertEquals(original.getModulus(), privateKey.getKeySpec().getModulus());

        privateKey.destroy();
        assertThrows(IllegalStateException.class, () -> privateKey.getModulus());
        assertThrows(IllegalStateException.class, () -> privateKey.getPrivateExponent());
        assertThrows(IllegalStateException.class, () -> privateKey.getKeySpec());
    }


    /**
     * N87 and N88: a key created from the key specification is encoded once, also by concurrent threads, and the
     * encoding is a valid PKCS#8 key.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testEncodeFromKeySpecConcurrent() throws Exception {
        KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(null, RSA, 2048);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        RSAPrivateCrtKeySpec keySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateCrtKeySpec.class);
        final RSAPrivateKeyPKCS8 privateKey = new RSAPrivateKeyPKCS8(keySpec);

        ExecutorService executor = Executors.newFixedThreadPool(THREADS);
        List<Future<byte[]>> results = new ArrayList<Future<byte[]>>();
        try {
            Callable<byte[]> task = () -> privateKey.getEncoded();
            for (int i = 0; i < THREADS; i++) {
                results.add(executor.submit(task));
            }

            byte[] first = results.get(0).get();
            assertNotNull(first);
            for (Future<byte[]> result : results) {
                assertArrayEquals(first, result.get());
            }

            RSAPrivateKey decoded = (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(first));
            assertEquals(keySpec.getModulus(), decoded.getModulus());
            assertEquals(keySpec.getPrivateExponent(), decoded.getPrivateExponent());
        } finally {
            executor.shutdownNow();
        }

        privateKey.checkEncoding();
        assertNotNull(privateKey.getEncoded());
    }


    /**
     * N85: invalid base64 is reported as checked exception.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testInvalidBase64() throws Exception {
        IKeyConverter[] converters = new IKeyConverter[] {new RSAKeyConverter(), new ECKeyConverter(), new DSAKeyConverter()};
        for (IKeyConverter converter : converters) {
            assertThrows(InvalidKeySpecException.class, () -> converter.getPrivateKey(INVALID_BASE64));
            assertThrows(InvalidKeySpecException.class, () -> converter.getPublicKey(INVALID_BASE64));
            assertThrows(InvalidKeySpecException.class, () -> converter.getPublicKey(INVALID_BASE64.getBytes()));
        }
    }


    /**
     * N85: whitespace (spaces, tabs, line breaks) inside and around the PEM data is ignored.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testWhitespaceInPem() throws Exception {
        assertWhitespaceInPem(KeyConverterFactory.getInstance().getConverter(RSA));
        assertWhitespaceInPem(KeyConverterFactory.getInstance().getConverter(EC));
    }


    /**
     * N86: the configured provider is used.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testConfiguredProvider() throws Exception {
        IKeyConverter rsaConverter = new RSAKeyConverter();
        KeyPair rsaKeyPair = rsaConverter.generateKeyPair();
        String rsaPublicKey = rsaConverter.formatPublicKey(rsaKeyPair.getPublic());
        String rsaPrivateKey = rsaConverter.formatPrivateKey(rsaKeyPair.getPrivate());
        assertNotNull(rsaConverter.getPublicKey(rsaPublicKey));
        assertNotNull(rsaConverter.getPrivateKey(rsaPrivateKey));

        IKeyConverter rsaProviderConverter = new RSAKeyConverter(NOT_EXISTING_PROVIDER);
        assertThrows(NoSuchProviderException.class, () -> rsaProviderConverter.getPublicKey(rsaPublicKey));
        assertThrows(NoSuchProviderException.class, () -> rsaProviderConverter.getPrivateKey(rsaPrivateKey));

        IKeyConverter ecConverter = new ECKeyConverter();
        KeyPair ecKeyPair = ecConverter.generateKeyPair();
        String ecPublicKey = ecConverter.formatPublicKey(ecKeyPair.getPublic());
        String ecPrivateKey = ecConverter.formatPrivateKey(ecKeyPair.getPrivate());
        IKeyConverter ecProviderConverter = new ECKeyConverter(NOT_EXISTING_PROVIDER);
        assertThrows(NoSuchProviderException.class, () -> ecProviderConverter.getPublicKey(ecPublicKey));
        assertThrows(NoSuchProviderException.class, () -> ecProviderConverter.getPrivateKey(ecPrivateKey));

        IKeyConverter dsaConverter = new DSAKeyConverter();
        KeyPair dsaKeyPair = dsaConverter.generateKeyPair();
        String dsaPublicKey = dsaConverter.formatPublicKey(dsaKeyPair.getPublic());
        IKeyConverter dsaProviderConverter = new DSAKeyConverter(NOT_EXISTING_PROVIDER);
        assertThrows(NoSuchProviderException.class, () -> dsaProviderConverter.getPublicKey(dsaPublicKey));
    }


    /**
     * N95: formatting a null public key returns null.
     */
    @Test
    public void testFormatNullPublicKey() {
        assertNull(new RSAKeyConverter().formatPublicKey(null));
        assertNull(new ECKeyConverter().formatPublicKey(null));
        assertNull(new DSAKeyConverter().formatPublicKey(null));
    }


    /**
     * N96: the key type of the factory is case-insensitive and ECDSA is the same as EC.
     */
    @Test
    public void testConverterType() {
        assertTrue(KeyConverterFactory.getInstance().getConverter("rsa") instanceof RSAKeyConverter);
        assertTrue(KeyConverterFactory.getInstance().getConverter(" Dsa ") instanceof DSAKeyConverter);
        assertTrue(KeyConverterFactory.getInstance().getConverter("ec") instanceof ECKeyConverter);
        assertTrue(KeyConverterFactory.getInstance().getConverter("ECDSA") instanceof ECKeyConverter);
        assertThrows(IllegalArgumentException.class, () -> KeyConverterFactory.getInstance().getConverter("XYZ"));
        assertThrows(IllegalArgumentException.class, () -> KeyConverterFactory.getInstance().getConverter((String) null));
    }


    /**
     * N99: non ASCII characters are rejected and can not become valid base64 characters.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testNonAsciiCharacter() throws Exception {
        // the cast of U+0141 to byte is 0x41, the base64 character 'A'
        assertThrows(IllegalArgumentException.class, () -> PKIUtil.getInstance().normalizeBuffer("MIIŁ", null, null));
        assertEquals("MIIA", PKIUtil.getInstance().normalizeBuffer("MII\nA", null, null));

        IKeyConverter converter = KeyConverterFactory.getInstance().getConverter(RSA);
        KeyPair keyPair = converter.generateKeyPair();
        String privateKeyPem = converter.formatPrivateKey(keyPair.getPrivate());
        String publicKeyPem = converter.formatPublicKey(keyPair.getPublic());
        assertNotNull(converter.getPrivateKey(privateKeyPem));

        String invalidPrivateKeyPem = replaceFirstBase64A(privateKeyPem);
        String invalidPublicKeyPem = replaceFirstBase64A(publicKeyPem);
        assertThrows(GeneralSecurityException.class, () -> converter.getPrivateKey(invalidPrivateKeyPem));
        assertThrows(GeneralSecurityException.class, () -> converter.getPublicKey(invalidPublicKeyPem));
    }


    /**
     * Assert that whitespace inside and around the PEM data is ignored.
     *
     * @param converter the converter
     * @throws Exception in case of error
     */
    private void assertWhitespaceInPem(IKeyConverter converter) throws Exception {
        KeyPair keyPair = converter.generateKeyPair();
        String privateKeyPem = "  " + converter.formatPrivateKey(keyPair.getPrivate()).replace("\n", " \t\r\n ") + " \n";
        String publicKeyPem = "  " + converter.formatPublicKey(keyPair.getPublic()).replace("\n", " \t\r\n ") + " \n";

        PrivateKey privateKey = converter.getPrivateKey(privateKeyPem);
        assertArrayEquals(keyPair.getPrivate().getEncoded(), privateKey.getEncoded());

        PublicKey publicKey = converter.getPublicKey(publicKeyPem);
        assertArrayEquals(keyPair.getPublic().getEncoded(), publicKey.getEncoded());
    }


    /**
     * Replace the first base64 character 'A' after the PEM header with U+0141, which is 'A' if it is cast to byte.
     *
     * @param pem the PEM data
     * @return the changed PEM data
     */
    private String replaceFirstBase64A(String pem) {
        int start = pem.indexOf('\n');
        int index = pem.indexOf('A', start);
        assertTrue(index > start);
        return pem.substring(0, index) + "Ł" + pem.substring(index + 1);
    }
}
