/*
 * CertificateVerifierTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.certificate.impl.CertificateVerifier;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the {@link CertificateVerifier}.
 *
 * @author patrick
 */
public class CertificateVerifierTest {
    private static final Logger LOG = LoggerFactory.getLogger(CertificateVerifierTest.class);


    /**
     * Test that revocation checking is disabled by default
     */
    @Test
    public void testRevocationDisabledByDefault() {
        CertificateVerifier verifier = new CertificateVerifier();
        assertFalse(verifier.isRevocationEnabled());
    }


    /**
     * Test enable/disable revocation checking via setter
     */
    @Test
    public void testSetRevocationEnabled() {
        CertificateVerifier verifier = new CertificateVerifier();
        verifier.setRevocationEnabled(true);
        assertTrue(verifier.isRevocationEnabled());
        verifier.setRevocationEnabled(false);
        assertFalse(verifier.isRevocationEnabled());
    }


    /**
     * Test verifyCertificateChain with null — should not throw
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testVerifyNullChain() throws GeneralSecurityException {
        CertificateVerifier verifier = new CertificateVerifier();
        verifier.verifyCertificateChain(LOG::debug, null);
    }


    /**
     * Test verifyCertificateChain with empty array — should not throw
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testVerifyEmptyChain() throws GeneralSecurityException {
        CertificateVerifier verifier = new CertificateVerifier();
        verifier.verifyCertificateChain(LOG::debug, new X509Certificate[0]);
    }


    /**
     * Test verification of a self-signed certificate
     *
     * @throws Exception in case of error
     */
    @Test
    public void testVerifySelfSignedCertificate() throws Exception {
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("TestCertVerifier");
        assertNotNull(certificateStore);

        X509Certificate[] chain = certificateStore.getCertificates();
        assertNotNull(chain);
        assertTrue(chain.length > 0);

        CertificateVerifier verifier = new CertificateVerifier();
        // should not throw — self-signed verification uses the cert's own public key
        verifier.verifyCertificateChain(LOG::debug, chain);
    }


    /**
     * Test verifyCertificate (single cert overload)
     *
     * @throws Exception in case of error
     */
    @Test
    public void testVerifySingleCertificate() throws Exception {
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("TestSingleCert");
        assertNotNull(certificateStore);

        X509Certificate cert = certificateStore.getCertificates()[0];

        ICertificateVerifier verifier = CertificateUtilFactory.getInstance().getVerifier();
        verifier.verifyCertificate(LOG::debug, cert);
    }


    /**
     * Test via the factory verifier (shared singleton) — chain verification without revocation
     *
     * @throws Exception in case of error
     */
    @Test
    public void testFactoryVerifierChain() throws Exception {
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("TestFactoryVerifier");
        assertNotNull(certificateStore);

        ICertificateVerifier verifier = CertificateUtilFactory.getInstance().getVerifier();
        verifier.verifyCertificateChain(LOG::debug, certificateStore.getCertificates());
    }
}
