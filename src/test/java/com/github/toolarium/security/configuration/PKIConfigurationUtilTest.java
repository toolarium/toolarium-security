/*
 * PKIConfigurationUtilTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.configuration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.certificate.util.CertificateTestUtil;
import com.github.toolarium.security.pki.KeyConverterFactory;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the {@link PKIConfigurationUtil}.
 * 
 * @author patrick
 */
public class PKIConfigurationUtilTest {
    private static final Logger LOG = LoggerFactory.getLogger(PKIConfigurationUtilTest.class);
    private static final String NL = "\n";
    private static final String RSA = "RSA";
    private static final String ALIAS = "test";

    
    /**
     * Test privat key use case.
     * 
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessible trust key-store
     */
    @Test
    void testPrivateKeySample() throws GeneralSecurityException, IOException {
        // create private key
        final PrivateKey privateKey = PKIUtil.getInstance().generateKeyPair(RSA, 2048).getPrivate();
        final String privateKeyStr = KeyConverterFactory.getInstance().getConverter(RSA).formatPrivateKey(privateKey);
        LOG.debug("Private key (log this never on any environemtent, its just a sample):" + NL + privateKeyStr);
        
        // ---------------------------------------------------
        // sample for services which need a private key: 
        final PrivateKey privateKey2 = PKIConfigurationUtil.getInstance().getPrivateKey(privateKeyStr);
        assertEquals(privateKey, privateKey2);
    }

    
    /**
     * Detect invalid public key
     *
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessible trust key-store
     */
    @Test
    void testWrongPrivateKey() throws GeneralSecurityException, IOException {
        final PrivateKey privateKey = PKIUtil.getInstance().generateKeyPair(RSA, 2048).getPrivate();
        final String privateKeyStr = KeyConverterFactory.getInstance().getConverter(RSA).formatPrivateKey(privateKey).replaceAll("PRIVATE", "PUBLIC");
        
        assertThrows(GeneralSecurityException.class, () -> {
            PKIConfigurationUtil.getInstance().getPublicKey(privateKeyStr); }, "Expected");
    }

    
    /**
     * Test public key use case.
     * 
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessible trust key-store
     */
    @Test
    void testPublicKeySample() throws GeneralSecurityException, IOException {
        // create private key
        final PublicKey publicKey = PKIUtil.getInstance().generateKeyPair(RSA, 2048).getPublic();
        final String publicKeyStr = KeyConverterFactory.getInstance().getConverter(RSA).formatPublicKey(publicKey);
        LOG.debug("Public key (log this never on any environemtent, its just a sample):" + NL + publicKeyStr);
        
        // ---------------------------------------------------
        // sample for services which need a public key: 
        final PublicKey publicKey2 = PKIConfigurationUtil.getInstance().getPublicKey(publicKeyStr);
        assertEquals(publicKey, publicKey2);
    }

    
    /**
     * Detect invalid public key
     *
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessible trust key-store
     */
    @Test
    void testWrongPublicKey() throws GeneralSecurityException, IOException {
        final PublicKey publicKey = PKIUtil.getInstance().generateKeyPair(RSA, 2048).getPublic();
        final String publicKeyStr = KeyConverterFactory.getInstance().getConverter(RSA).formatPublicKey(publicKey).replaceAll("PUBLIC", "PRIVATE");
        
        assertThrows(GeneralSecurityException.class, () -> {
            PKIConfigurationUtil.getInstance().getPublicKey(publicKeyStr); }, "Expected");
    }

    
    /**
     * Test use case.
     * 
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessible trust key-store
     */
    @Test
    void testKeyStoreSample() throws GeneralSecurityException, IOException {
        // create self signed certificates
        final List<X509Certificate> list = CertificateTestUtil.getInstance().createSelfSignedCertificates();
        
        // convert to string
        final String certifivcateStr = CertificateUtilFactory.getInstance().getConverter().formatPKCS7(list.stream().toArray(X509Certificate[]::new));
        LOG.debug("Certificate chain (log this never on any environemtent, its just a sample):" + NL + certifivcateStr);
        
        // ---------------------------------------------------
        // sample for services which need a trust store: 
        // get trust key-store with added certificate chain
        final KeyStore keyStore = PKIConfigurationUtil.getInstance().getKeyStore(ALIAS, certifivcateStr);
        
        // ---------------------------------------------------
        
        LOG.debug("Keystore: type=" + keyStore.getType() + ", provider: " + keyStore.getProvider());
        
        List<X509Certificate> validCertificates = CertificateUtilFactory.getInstance().getFilter().filterValid(list);
        assertEquals(3, validCertificates.size());
        List<X509Certificate> notYetValidCertificates = CertificateUtilFactory.getInstance().getFilter().filterNotYedValid(list);
        assertEquals(2, notYetValidCertificates.size());
       
        assertEquals(validCertificates.get(0), keyStore.getCertificate(ALIAS + "0"));
        assertEquals(validCertificates.get(1), keyStore.getCertificate(ALIAS + "1"));
        assertEquals(validCertificates.get(2), keyStore.getCertificate(ALIAS + "2"));
        assertEquals(notYetValidCertificates.get(0), keyStore.getCertificate(ALIAS + "3"));
        assertEquals(notYetValidCertificates.get(1), keyStore.getCertificate(ALIAS + "4"));
    }

    
    /**
     * Detect invalid certificate
     *
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessible trust keystore
     */
    @Test
    void testWrongCertificate() throws GeneralSecurityException, IOException {
        final PublicKey publicKey = PKIUtil.getInstance().generateKeyPair(RSA, 2048).getPublic();
        final String publicKeyStr = KeyConverterFactory.getInstance().getConverter(RSA).formatPublicKey(publicKey);
        
        assertThrows(GeneralSecurityException.class, () -> {
            PKIConfigurationUtil.getInstance().getKeyStore(ALIAS, publicKeyStr); }, "Expected");
    }


    /**
     * Test use case.
     * 
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessible trust keystore
     */
    @Test
    void testTrustKeyStoreSample() throws GeneralSecurityException, IOException {
        // create self signed certificates
        final List<X509Certificate> list = CertificateTestUtil.getInstance().createSelfSignedCertificates();
        
        // convert to string
        final String certifivcateStr = CertificateUtilFactory.getInstance().getConverter().formatPKCS7(list.stream().toArray(X509Certificate[]::new));
        LOG.debug("==>" + certifivcateStr);
        
        // ---------------------------------------------------
        // sample for services which need a trust store: 
        // get trust keystore with added certificate chain
        final KeyStore trustKeyStore = PKIConfigurationUtil.getInstance().getTrustKeyStore(ALIAS, certifivcateStr);
        
        // ---------------------------------------------------
        
        LOG.debug("Keystore: type=" + trustKeyStore.getType() + ", provider: " + trustKeyStore.getProvider());
        
        List<X509Certificate> validCertificates = CertificateUtilFactory.getInstance().getFilter().filterValid(list);
        assertEquals(3, validCertificates.size());
        List<X509Certificate> notYetValidCertificates = CertificateUtilFactory.getInstance().getFilter().filterNotYedValid(list);
        assertEquals(2, notYetValidCertificates.size());
        
        assertEquals(validCertificates.get(0), trustKeyStore.getCertificate(ALIAS + "0"));
        assertEquals(validCertificates.get(1), trustKeyStore.getCertificate(ALIAS + "1"));
        assertEquals(validCertificates.get(2), trustKeyStore.getCertificate(ALIAS + "2"));
        assertEquals(notYetValidCertificates.get(0), trustKeyStore.getCertificate(ALIAS + "3"));
        assertEquals(notYetValidCertificates.get(1), trustKeyStore.getCertificate(ALIAS + "4"));
    }
}
