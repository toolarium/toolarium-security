/*
 * CertificateVerifierTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.certificate.impl.CertificateVerifier;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
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
    private static final String KEY_ALGORITHM = "RSA";
    private static final String TEST_HOST = "localhost";


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
     * Test verifyCertificateChain with null consumer — should not throw (null consumer is valid)
     *
     * @throws Exception in case of error
     */
    @Test
    public void testVerifyChainWithNullConsumer() throws Exception {
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("TestNullConsumer");
        assertNotNull(certificateStore);

        CertificateVerifier verifier = new CertificateVerifier();
        // null consumer must not cause NullPointerException
        verifier.verifyCertificateChain(null, certificateStore.getCertificates());
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
     * Test verifyCertificate (single cert overload, self-signed)
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
     * Test verifyCertificate (single cert overload) with null certificate — must throw GeneralSecurityException
     */
    @Test
    public void testVerifyNullCertificateThrows() {
        CertificateVerifier verifier = new CertificateVerifier();
        assertThrows(GeneralSecurityException.class, () -> verifier.verifyCertificate(LOG::debug, (X509Certificate) null));
    }


    /**
     * Test verifyCertificate (two-arg overload) with CA cert — leaf verified against its issuer
     *
     * @throws Exception in case of error
     */
    @Test
    public void testVerifyCertificateWithCa() throws Exception {
        KeyPair caKeyPair = PKIUtil.getInstance().generateKeyPair(null, KEY_ALGORITHM, 2048);
        CertificateStore caStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate(caKeyPair, "TestCA", TEST_HOST, new Date(), 365);
        assertNotNull(caStore);

        CertificateStore leafStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate(PKIUtil.getInstance().generateKeyPair(null, KEY_ALGORITHM, 2048),
                        caStore, "TestLeaf", TEST_HOST, new Date(), 365);
        assertNotNull(leafStore);

        // chain is [leaf, ca]; verify leaf against CA cert (index 0 vs index 1)
        X509Certificate leafCert = leafStore.getCertificates()[0];
        X509Certificate caCert = leafStore.getCertificates()[1];

        CertificateVerifier verifier = new CertificateVerifier();
        // should succeed: leaf was signed by CA
        verifier.verifyCertificate(LOG::debug, leafCert, caCert);
    }


    /**
     * Test verifyCertificate (two-arg overload) with wrong CA cert — must throw
     *
     * @throws Exception in case of error
     */
    @Test
    public void testVerifyCertificateWithWrongCaThrows() throws Exception {
        CertificateStore caStore1 = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("WrongCA1");
        CertificateStore caStore2 = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("WrongCA2");
        assertNotNull(caStore1);
        assertNotNull(caStore2);

        X509Certificate cert1 = caStore1.getCertificates()[0];
        X509Certificate cert2 = caStore2.getCertificates()[0];

        CertificateVerifier verifier = new CertificateVerifier();
        // cert1 was NOT signed by cert2 — verification must fail
        assertThrows(GeneralSecurityException.class, () -> verifier.verifyCertificate(LOG::debug, cert1, cert2));
    }


    /**
     * Test verifyCertificate (two-arg overload) with null caCert — self-signed path
     *
     * @throws Exception in case of error
     */
    @Test
    public void testVerifyCertificateWithNullCa() throws Exception {
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("TestNullCA");
        assertNotNull(certificateStore);

        X509Certificate cert = certificateStore.getCertificates()[0];

        CertificateVerifier verifier = new CertificateVerifier();
        // null caCert triggers the self-signed path (verify against own public key)
        verifier.verifyCertificate(LOG::debug, cert, null);
    }


    /**
     * Test verifyCertificateChain with a two-cert chain (leaf + root CA) without revocation
     *
     * @throws Exception in case of error
     */
    @Test
    public void testVerifyTwoCertChain() throws Exception {
        KeyPair caKeyPair = PKIUtil.getInstance().generateKeyPair(null, KEY_ALGORITHM, 2048);
        CertificateStore caStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate(caKeyPair, "ChainCA", TEST_HOST, new Date(), 365);
        assertNotNull(caStore);

        CertificateStore leafStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate(PKIUtil.getInstance().generateKeyPair(null, KEY_ALGORITHM, 2048),
                        caStore, "ChainLeaf", TEST_HOST, new Date(), 365);
        assertNotNull(leafStore);

        X509Certificate[] chain = leafStore.getCertificates();
        assertNotNull(chain);
        assertTrue(chain.length == 2);

        CertificateVerifier verifier = new CertificateVerifier();
        verifier.verifyCertificateChain(LOG::debug, chain);
    }


    /**
     * Test verifyCertificateChain with revocation enabled on a single self-signed cert.
     * The pathLength will be 0, so revocation must be skipped (early return), not throw.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRevocationEnabledSingleSelfSignedCert() throws Exception {
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("TestRevocationSingle");
        assertNotNull(certificateStore);

        CertificateVerifier verifier = new CertificateVerifier();
        verifier.setRevocationEnabled(true);
        // single self-signed cert: pathLength < 1 → early return inside verifyRevocation
        verifier.verifyCertificateChain(LOG::debug, certificateStore.getCertificates());
    }


    /**
     * Test verifyCertificateChain with revocation enabled on a two-cert chain.
     * Self-generated certs have no CRL/OCSP endpoints; SOFT_FAIL must prevent a failure.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRevocationEnabledTwoCertChain() throws Exception {
        KeyPair caKeyPair = PKIUtil.getInstance().generateKeyPair(null, KEY_ALGORITHM, 2048);
        CertificateStore caStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate(caKeyPair, "RevCA", TEST_HOST, new Date(), 365);
        assertNotNull(caStore);

        CertificateStore leafStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate(PKIUtil.getInstance().generateKeyPair(null, KEY_ALGORITHM, 2048),
                        caStore, "RevLeaf", TEST_HOST, new Date(), 365);
        assertNotNull(leafStore);

        X509Certificate[] chain = leafStore.getCertificates();
        assertNotNull(chain);
        assertTrue(chain.length == 2);

        CertificateVerifier verifier = new CertificateVerifier();
        verifier.setRevocationEnabled(true);
        // SOFT_FAIL ensures missing CRL/OCSP endpoints do not cause a failure
        verifier.verifyCertificateChain(LOG::debug, chain);
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
