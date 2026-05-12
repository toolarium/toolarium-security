/*
 * CertificateVerifier.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.impl;

import com.github.toolarium.security.certificate.ICertificateVerifier;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Implements the {@link ICertificateVerifier}
 * 
 * @author patrick
 */
public class CertificateVerifier implements ICertificateVerifier {
    private static final Logger LOG = LoggerFactory.getLogger(CertificateVerifier.class);
    private boolean revocationEnabled;


    /**
     * Constructor for CertificateVerifier
     */
    public CertificateVerifier() {
        this.revocationEnabled = false;
    }


    /**
     * Enable or disable certificate revocation checking (CRL/OCSP).
     * When enabled, the JDK's PKIX CertPathValidator is used to check revocation status
     * based on CRL Distribution Points and Authority Information Access extensions in the certificates.
     *
     * <p>Revocation checking is disabled by default for backward compatibility.
     * Self-signed certificates typically have no CRL endpoints, so enabling this
     * is only useful for certificates issued by a CA that publishes CRLs or supports OCSP.</p>
     *
     * @param revocationEnabled true to enable revocation checking
     */
    public void setRevocationEnabled(boolean revocationEnabled) {
        this.revocationEnabled = revocationEnabled;
    }


    /**
     * Check if revocation checking is enabled.
     *
     * @return true if revocation checking is enabled
     */
    public boolean isRevocationEnabled() {
        return revocationEnabled;
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateVerifier#verifyCertificateChain(java.util.function.Consumer, java.security.cert.X509Certificate[])
     */
    @Override
    public void verifyCertificateChain(Consumer<String> consumer, X509Certificate[] certs) throws GeneralSecurityException {
        if (certs == null || certs.length == 0) {
            return;
        }

        int anz = certs.length;
        if (consumer != null) {
            PKIUtil.getInstance().processCertificate(consumer, "Verify certificate chain: " + anz + " certificate(s)...", certs);
        }

        verifyCertificate(consumer, certs[anz - 1], null);
        for (int i = anz - 1; i > 0; i--) {
            verifyCertificate(consumer, certs[i - 1], certs[i]);
        }

        if (revocationEnabled) {
            verifyRevocation(consumer, certs);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Certificate chain checked successful!");
        }
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateVerifier#verifyCertificate(java.util.function.Consumer, java.security.cert.X509Certificate, java.security.cert.X509Certificate)
     */
    @Override
    public void verifyCertificate(Consumer<String> consumer, X509Certificate userCert, X509Certificate caCert) throws GeneralSecurityException {
        if (caCert != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Verify certificate: '" + userCert.getSubjectX500Principal().getName() + "'");
            }
            userCert.verify(caCert.getPublicKey());

            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully verified CA certificate with public key.");
            }
            if (consumer != null) {
                PKIUtil.getInstance().processPublicKeyInfo(consumer, null, caCert.getPublicKey());
            }
        } else {
            // self-signed root: verify signature with own public key
            if (LOG.isDebugEnabled()) {
                LOG.debug("Verify self-signed root certificate: '" + userCert.getSubjectX500Principal().getName() + "'");
            }
            userCert.verify(userCert.getPublicKey());
        }
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateVerifier#verifyCertificate(java.util.function.Consumer, java.security.cert.X509Certificate)
     */
    @Override
    public void verifyCertificate(Consumer<String> consumer, X509Certificate userCertificate) throws GeneralSecurityException {
        if (userCertificate == null) {
            throw new GeneralSecurityException("Invalid certificate (null)!");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Verify certificate: '" + userCertificate.getSubjectX500Principal().getName() + "'");
        }
        userCertificate.verify(userCertificate.getPublicKey());

        if (LOG.isDebugEnabled()) {
            LOG.debug("Successfully verified CA certificate with its own public key.");
        }
        if (consumer != null) {
            PKIUtil.getInstance().processPublicKeyInfo(consumer, null, userCertificate.getPublicKey());
        }
    }


    /**
     * Verify revocation status of the certificate chain using the JDK's PKIX CertPathValidator.
     * The root certificate (last in chain) is used as the trust anchor.
     *
     * @param consumer the consumer for log output
     * @param certs the certificate chain
     * @throws GeneralSecurityException if revocation check fails
     */
    private void verifyRevocation(Consumer<String> consumer, X509Certificate[] certs) throws GeneralSecurityException {
        if (certs.length < 1) {
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Checking certificate revocation status...");
        }

        // the root (last cert) is the trust anchor
        X509Certificate rootCert = certs[certs.length - 1];
        TrustAnchor trustAnchor = new TrustAnchor(rootCert, null);

        // build cert path from the chain (excluding the root)
        int pathLength = certs.length - 1;
        if (pathLength < 1) {
            // single self-signed cert — no revocation path to validate
            if (LOG.isDebugEnabled()) {
                LOG.debug("Single self-signed certificate, skipping revocation check.");
            }
            return;
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath certPath = cf.generateCertPath(Arrays.asList(Arrays.copyOf(certs, pathLength)));

        PKIXParameters params = new PKIXParameters(Collections.singleton(trustAnchor));
        params.setRevocationEnabled(true);

        // enable OCSP if available
        System.setProperty("com.sun.security.enableCRLDP", "true");

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        validator.validate(certPath, params);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Certificate revocation check passed.");
        }
        if (consumer != null) {
            consumer.accept("Certificate revocation check passed.");
        }
    }
}
