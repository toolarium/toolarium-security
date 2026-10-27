/*
 * KeyStoreUtilTrustStoreTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import com.github.toolarium.security.certificate.CertificateUtilFactory;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;


/**
 * Test that adding certificates to the default trust keystore does not change it unless requested (N8).
 *
 * @author patrick
 */
public class KeyStoreUtilTrustStoreTest {

    /**
     * Constructor for KeyStoreUtilTrustStoreTest
     */
    public KeyStoreUtilTrustStoreTest() {
        // NOP
    }


    /**
     * Adding a certificate without global flag only changes a copy of the default trust keystore.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testAddCertificateLocal() throws Exception {
        X509Certificate cert = createCertificate("local.example.com");
        KeyStore defaultTrustKeyStore = KeyStoreUtil.getInstance().getDefaultTrustKeyStore();
        int defaultSize = defaultTrustKeyStore.size();

        KeyStore trustKeyStore = KeyStoreUtil.getInstance().addCertificateToTrustKeystore("n8-local", cert);
        assertNotSame(defaultTrustKeyStore, trustKeyStore);
        assertEquals(defaultSize + 1, trustKeyStore.size());
        assertNotNull(trustKeyStore.getCertificateAlias(cert));

        // the shared default trust keystore is unchanged
        assertSame(defaultTrustKeyStore, KeyStoreUtil.getInstance().getDefaultTrustKeyStore());
        assertEquals(defaultSize, KeyStoreUtil.getInstance().getDefaultTrustKeyStore().size());
        assertNull(KeyStoreUtil.getInstance().getDefaultTrustKeyStore().getCertificateAlias(cert));
    }


    /**
     * Adding a certificate with global flag changes the shared default trust keystore (copy on write).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testAddCertificateGlobal() throws Exception {
        X509Certificate cert = createCertificate("global.example.com");
        KeyStore previousTrustKeyStore = KeyStoreUtil.getInstance().getDefaultTrustKeyStore();
        int previousSize = previousTrustKeyStore.size();

        KeyStore trustKeyStore = KeyStoreUtil.getInstance().addCertificateToTrustKeystore("n8-global", new X509Certificate[] {cert}, true);
        assertSame(trustKeyStore, KeyStoreUtil.getInstance().getDefaultTrustKeyStore());
        assertNotNull(KeyStoreUtil.getInstance().getDefaultTrustKeyStore().getCertificateAlias(cert));
        assertEquals(previousSize + 1, trustKeyStore.size());

        // a keystore which was returned before is not modified
        assertNotSame(previousTrustKeyStore, trustKeyStore);
        assertEquals(previousSize, previousTrustKeyStore.size());
        assertNull(previousTrustKeyStore.getCertificateAlias(cert));
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
