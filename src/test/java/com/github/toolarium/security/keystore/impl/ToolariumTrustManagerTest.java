/*
 * ToolariumTrustManagerTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.impl;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.certificate.impl.CertificateVerifier;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;


/**
 * Test the {@link ToolariumTrustManager}.
 *
 * @author patrick
 */
public class ToolariumTrustManagerTest {
    private static final String HOST = "myhost.example.com";
    private static final String RSA = "RSA";
    private static final String WWW_HOST = "www.example.com";
    private static final String WILDCARD_HOST = "*.example.com";


    /**
     * Constructor for ToolariumTrustManagerTest
     */
    public ToolariumTrustManagerTest() {
        // NOP
    }


    /**
     * The server certificate matches the configured host name (subject alternative name) (S17).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testHostnameMatches() throws Exception {
        X509Certificate cert = createCertificate(HOST);
        ToolariumTrustManager trustManager = new ToolariumTrustManager(HOST);
        trustManager.addTrustedCertificate(cert);
        assertDoesNotThrow(() -> trustManager.checkServerTrusted(new X509Certificate[] {cert}, RSA));

        // case-insensitive and the additional SAN localhost
        trustManager.setHostname("MyHost.Example.COM");
        assertDoesNotThrow(() -> trustManager.checkServerTrusted(new X509Certificate[] {cert}, RSA));
        trustManager.setHostname("localhost");
        assertDoesNotThrow(() -> trustManager.checkServerTrusted(new X509Certificate[] {cert}, RSA));
    }


    /**
     * The server certificate does not match the configured host name (S17).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testHostnameMismatch() throws Exception {
        X509Certificate cert = createCertificate(HOST);
        ToolariumTrustManager trustManager = new ToolariumTrustManager("other.example.com");
        trustManager.addTrustedCertificate(cert);
        assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(new X509Certificate[] {cert}, RSA));
    }


    /**
     * Without host name the verification is skipped (backward compatible).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testNoHostname() throws Exception {
        X509Certificate cert = createCertificate(HOST);
        ToolariumTrustManager trustManager = new ToolariumTrustManager();
        trustManager.addTrustedCertificate(cert);
        assertDoesNotThrow(() -> trustManager.checkServerTrusted(new X509Certificate[] {cert}, RSA));
    }


    /**
     * Test the DNS name matching including wildcards (S17).
     */
    @Test
    public void testMatchesDnsName() {
        ToolariumTrustManager trustManager = new ToolariumTrustManager();
        assertTrue(trustManager.matchesDnsName(WWW_HOST, "WWW.example.com"));
        assertTrue(trustManager.matchesDnsName(WWW_HOST + ".", WWW_HOST));
        assertTrue(trustManager.matchesDnsName(WILDCARD_HOST, WWW_HOST));
        assertFalse(trustManager.matchesDnsName(WILDCARD_HOST, "example.com"));
        assertFalse(trustManager.matchesDnsName(WILDCARD_HOST, "a.b.example.com"));
        assertFalse(trustManager.matchesDnsName("*.com", "example.com"));
        assertFalse(trustManager.matchesDnsName("w*.example.com", WWW_HOST));
        assertFalse(trustManager.matchesDnsName(WWW_HOST, "www.example.org"));
        assertFalse(trustManager.matchesDnsName(null, WWW_HOST));
        assertFalse(trustManager.matchesDnsName("", ""));
    }


    /**
     * Every caller gets an own verifier: a changed configuration does not affect other callers (N20).
     */
    @Test
    public void testOwnVerifierPerCaller() {
        CertificateVerifier first = (CertificateVerifier) CertificateUtilFactory.getInstance().getVerifier();
        CertificateVerifier second = (CertificateVerifier) CertificateUtilFactory.getInstance().getVerifier();
        assertNotSame(first, second);

        first.setRevocationEnabled(true);
        assertTrue(first.isRevocationEnabled());
        assertFalse(second.isRevocationEnabled());
        assertFalse(((CertificateVerifier) CertificateUtilFactory.getInstance().getVerifier()).isRevocationEnabled());
    }


    /**
     * Create a self-signed certificate
     *
     * @param dn the dn
     * @return the certificate
     * @throws Exception in case of error
     */
    private X509Certificate createCertificate(String dn) throws Exception {
        return CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(dn).getCertificates()[0];
    }
}
