/*
 * TrustedCertificatesTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.common.security.ISecuredSecretValue;
import com.github.toolarium.common.security.SecuredValueFactory;
import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.certificate.impl.CertificateVerifier;
import com.github.toolarium.security.keystore.util.KeyStoreUtil;
import com.github.toolarium.security.pki.util.PKIUtil;
import com.github.toolarium.security.ssl.SSLContextFactory;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;


/**
 * Test the trusted certificates of the {@link ToolariumTrustManager} and the {@link CertificateVerifier}, the CA
 * certificates of the generator, the keystore writing and the recommended cipher suites.
 *
 * @author patrick
 */
public class TrustedCertificatesTest {
    private static final String RSA = "RSA";
    private static final String HOST_A = "a.example.com";
    private static final String HOST_B = "b.example.com";

    /** the temporary directory */
    @TempDir
    private File tempDir;


    /**
     * Constructor for TrustedCertificatesTest
     */
    public TrustedCertificatesTest() {
        // NOP
    }


    /**
     * Two server certificates of the same CA are both trusted (before the second replaced the first).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testTwoServerCertificatesOfSameCa() throws Exception {
        CertificateStore ca = CertificateUtilFactory.getInstance().getGenerator().createCACertificate("Test CA", 365);
        X509Certificate serverA = createServerCertificate(ca, HOST_A);
        X509Certificate serverB = createServerCertificate(ca, HOST_B);

        ToolariumTrustManager trustManager = new ToolariumTrustManager();
        trustManager.addTrustedCertificate(ca.getCertificates()[0]);
        trustManager.addTrustedCertificate(serverA);
        trustManager.addTrustedCertificate(serverB);
        assertDoesNotThrow(() -> trustManager.checkServerTrusted(new X509Certificate[] {serverA, ca.getCertificates()[0]}, RSA));
        assertDoesNotThrow(() -> trustManager.checkServerTrusted(new X509Certificate[] {serverB, ca.getCertificates()[0]}, RSA));

        // a certificate of an other CA is still rejected
        CertificateStore otherCa = CertificateUtilFactory.getInstance().getGenerator().createCACertificate("Other CA", 365);
        X509Certificate other = createServerCertificate(otherCa, HOST_A);
        assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(new X509Certificate[] {other, otherCa.getCertificates()[0]}, RSA));
    }


    /**
     * Certificates accepted while the verification is off are not remembered: after the verification is enabled again
     * they are rejected.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testNoTrustWithoutVerification() throws Exception {
        CertificateStore ca = CertificateUtilFactory.getInstance().getGenerator().createCACertificate("Test CA", 365);
        X509Certificate server = createServerCertificate(ca, HOST_A);
        CertificateStore otherCa = CertificateUtilFactory.getInstance().getGenerator().createCACertificate("Other CA", 365);
        final X509Certificate[] otherChain = new X509Certificate[] {createServerCertificate(otherCa, HOST_A), otherCa.getCertificates()[0]};

        ToolariumTrustManager trustManager = new ToolariumTrustManager();
        trustManager.addTrustedCertificate(ca.getCertificates()[0]);
        trustManager.addTrustedCertificate(server);

        trustManager.setVerifyCertificate(false);
        assertDoesNotThrow(() -> trustManager.checkServerTrusted(otherChain, RSA));

        trustManager.setVerifyCertificate(true);
        assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(otherChain, RSA));
        assertDoesNotThrow(() -> trustManager.checkServerTrusted(new X509Certificate[] {server, ca.getCertificates()[0]}, RSA));
    }


    /**
     * With a trust list the root certificate must be one of the trusted certificates.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testVerifierTrustedCertificates() throws Exception {
        CertificateStore ca = CertificateUtilFactory.getInstance().getGenerator().createCACertificate("Trusted CA", 365);
        CertificateStore otherCa = CertificateUtilFactory.getInstance().getGenerator().createCACertificate("Other CA", 365);
        X509Certificate[] chain = new X509Certificate[] {createServerCertificate(ca, HOST_A), ca.getCertificates()[0]};
        X509Certificate[] otherChain = new X509Certificate[] {createServerCertificate(otherCa, HOST_A), otherCa.getCertificates()[0]};

        // default: no trust list, any self-signed root passes
        CertificateVerifier verifier = new CertificateVerifier();
        assertDoesNotThrow(() -> verifier.verifyCertificateChain(null, otherChain));

        verifier.setTrustedCertificates(Collections.singletonList(ca.getCertificates()[0]));
        assertDoesNotThrow(() -> verifier.verifyCertificateChain(null, chain));
        assertThrows(CertificateException.class, () -> verifier.verifyCertificateChain(null, otherChain));

        // key store overload
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", otherCa.getCertificates()[0]);
        verifier.setTrustedCertificates(trustStore);
        assertDoesNotThrow(() -> verifier.verifyCertificateChain(null, otherChain));
        assertThrows(CertificateException.class, () -> verifier.verifyCertificateChain(null, chain));
    }


    /**
     * A CA certificate can sign certificates, a normal certificate is no CA.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testCaCertificate() throws Exception {
        CertificateStore ca = CertificateUtilFactory.getInstance().getGenerator().createCACertificate("CA", 365);
        assertTrue(ca.getCertificates()[0].getBasicConstraints() >= 0);
        assertTrue(ca.getCertificates()[0].getKeyUsage()[5]);

        CertificateStore intermediate = CertificateUtilFactory.getInstance().getGenerator()
                .createCACertificate(PKIUtil.getInstance().generateKeyPair(null, RSA, 2048), ca, "Intermediate CA", new Date(), 365);
        assertTrue(intermediate.getCertificates()[0].getBasicConstraints() >= 0);
        assertEquals(2, intermediate.getCertificates().length);

        CertificateStore server = CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(HOST_A);
        assertEquals(-1, server.getCertificates()[0].getBasicConstraints());
    }


    /**
     * An existing keystore which can not be read is not overwritten.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testUnreadableKeystoreIsNotOverwritten() throws Exception {
        CertificateStore store = CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(HOST_A);
        String fileName = new File(tempDir, "test.p12").getPath();
        ISecuredSecretValue password = SecuredValueFactory.getInstance().createSecret("secret".toCharArray(), "...");
        ISecuredSecretValue wrongPassword = SecuredValueFactory.getInstance().createSecret("wrong".toCharArray(), "...");

        KeyStoreUtil.getInstance().writePKCS12KeyStore(fileName, "a", store.getKeyPair().getPrivate(), store.getCertificates(), password);
        byte[] content = Files.readAllBytes(new File(fileName).toPath());
        assertThrows(Exception.class,
            () -> KeyStoreUtil.getInstance().writePKCS12KeyStore(fileName, "b", store.getKeyPair().getPrivate(), store.getCertificates(), wrongPassword));
        assertArrayEquals(content, Files.readAllBytes(new File(fileName).toPath()));

        // with the right password the entry is added
        KeyStoreUtil.getInstance().writePKCS12KeyStore(fileName, "b", store.getKeyPair().getPrivate(), store.getCertificates(), password);
        KeyStore keyStore = KeyStoreUtil.getInstance().readPKCS12KeyStore(fileName, password);
        assertTrue(keyStore.containsAlias("a"));
        assertTrue(keyStore.containsAlias("b"));
        assertEquals(1, tempDir.listFiles().length, "no temporary file left");
    }


    /**
     * The recommended cipher suites are returned as copy.
     */
    @Test
    public void testRecommendedCipherSuitesCopy() {
        String[] cipherSuites = SSLContextFactory.getInstance().getRecommendedCipherSuites();
        String first = cipherSuites[0];
        cipherSuites[0] = "TLS_RSA_WITH_NULL_SHA";
        assertEquals(first, SSLContextFactory.getInstance().getRecommendedCipherSuites()[0]);
        assertNotEquals(cipherSuites[0], SSLContextFactory.getInstance().getRecommendedCipherSuites()[0]);
    }


    /**
     * Create a server certificate with an own key pair, signed by the given CA.
     *
     * @param ca the CA
     * @param host the host name
     * @return the server certificate
     * @throws Exception in case of error
     */
    private X509Certificate createServerCertificate(CertificateStore ca, String host) throws Exception {
        return CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate(PKIUtil.getInstance().generateKeyPair(null, RSA, 2048), ca, host, host, new Date(), 365).getCertificates()[0];
    }
}
