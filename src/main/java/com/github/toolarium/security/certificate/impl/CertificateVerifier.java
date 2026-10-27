/*
 * CertificateVerifier.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.impl;

import com.github.toolarium.security.certificate.ICertificateVerifier;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Implements the {@link ICertificateVerifier}
 *
 * <p><strong>WARNING:</strong> Certificate revocation checking (CRL/OCSP) is <em>disabled</em>
 * by default. A revoked certificate will pass validation unless revocation is explicitly
 * enabled via {@link #setRevocationEnabled(boolean)}. Enable it in production for any
 * certificate chain issued by a CA that publishes CRLs or supports OCSP.</p>
 *
 * @author patrick
 */
public class CertificateVerifier implements ICertificateVerifier {
    private static final Logger LOG = LoggerFactory.getLogger(CertificateVerifier.class);
    private static final int KEY_USAGE_KEY_CERT_SIGN = 5;
    private volatile boolean revocationEnabled;
    private volatile boolean revocationStrict;
    private volatile boolean strictChainValidation;
    private volatile Set<X509Certificate> trustedCertificates;
    private final AtomicBoolean missingTrustedCertificatesWarningLogged;


    /**
     * Constructor for CertificateVerifier.
     *
     * <p><strong>WARNING:</strong> Revocation checking is disabled by default.
     * Call {@link #setRevocationEnabled(boolean) setRevocationEnabled(true)} to enable
     * CRL/OCSP checking in production environments.</p>
     */
    public CertificateVerifier() {
        this.revocationEnabled = false;
        this.strictChainValidation = true;
        this.trustedCertificates = null;
        this.missingTrustedCertificatesWarningLogged = new AtomicBoolean(false);
    }


    /**
     * Set the trusted (root) certificates. If set, the root certificate of a verified chain (the last certificate)
     * must be one of them, otherwise the chain is rejected. If not set (default), the root certificate is only
     * verified with its own signature, which any self-signed certificate passes.
     *
     * @param trustedCertificates the trusted certificates, null to remove the trust list (an empty collection trusts nothing)
     */
    public void setTrustedCertificates(Collection<X509Certificate> trustedCertificates) {
        if (trustedCertificates == null) {
            this.trustedCertificates = null;
        } else {
            this.trustedCertificates = Collections.unmodifiableSet(new HashSet<>(trustedCertificates));
        }
    }


    /**
     * Set the trusted (root) certificates from all certificate entries of the given key store,
     * see {@link #setTrustedCertificates(Collection)}.
     *
     * @param trustKeyStore the key store with the trusted certificates, null to remove the trust list
     * @throws KeyStoreException if the key store can not be read
     */
    public void setTrustedCertificates(KeyStore trustKeyStore) throws KeyStoreException {
        if (trustKeyStore == null) {
            setTrustedCertificates((Collection<X509Certificate>) null);
            return;
        }

        List<X509Certificate> certificates = new ArrayList<>();
        for (String alias : Collections.list(trustKeyStore.aliases())) {
            Certificate certificate = trustKeyStore.getCertificate(alias);
            if (certificate instanceof X509Certificate) {
                certificates.add((X509Certificate) certificate);
            }
        }
        setTrustedCertificates(certificates);
    }


    /**
     * Get the trusted (root) certificates.
     *
     * @return the trusted certificates or null if no trust list is set
     */
    public Set<X509Certificate> getTrustedCertificates() {
        return trustedCertificates;
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
     * Enable or disable the strict revocation mode. It is only used if revocation checking is enabled.
     *
     * <p>A revoked certificate is always rejected. The strict mode decides what happens if the revocation status
     * can not be determined (no OCSP responder / CRL distribution point, or not reachable): by default (false) the
     * certificate is accepted and a warning is logged; in strict mode (true) the certificate is rejected.</p>
     *
     * @param revocationStrict true to reject certificates with an unknown revocation status
     */
    public void setRevocationStrict(boolean revocationStrict) {
        this.revocationStrict = revocationStrict;
    }


    /**
     * Check if the strict revocation mode is enabled.
     *
     * @return true if certificates with an unknown revocation status are rejected
     */
    public boolean isRevocationStrict() {
        return revocationStrict;
    }


    /**
     * Enable or disable the strict chain validation, enabled by default. Besides the signatures it verifies the
     * validity dates of every certificate in the chain and that every issuer is a CA (basic constraints) which is
     * allowed to sign certificates (key usage <code>keyCertSign</code>, if the key usage extension is present).
     *
     * @param strictChainValidation false to verify the signatures only (behaviour of version 1.1.8 and older)
     */
    public void setStrictChainValidation(boolean strictChainValidation) {
        this.strictChainValidation = strictChainValidation;
    }


    /**
     * Check if the strict chain validation is enabled.
     *
     * @return true if the validity dates, basic constraints and key usage are verified
     */
    public boolean isStrictChainValidation() {
        return strictChainValidation;
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

        verifyTrustedRoot(certs[anz - 1]);

        if (strictChainValidation) {
            verifyChainConstraints(certs);
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
            // self-signed root: verify signature with own public key.
            // WARNING: this only proves the certificate is self-consistent; it does NOT verify
            // that the root is present in a trusted anchor store. Any arbitrary self-signed
            // certificate will pass this check. For full trust-anchor validation, callers must
            // perform an additional check against a trusted KeyStore.
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
     * Verify that the root certificate is one of the trusted certificates, if a trust list is set.
     *
     * @param rootCertificate the root certificate (the last certificate of the chain)
     * @throws CertificateException if a trust list is set and the root certificate is not part of it
     */
    private void verifyTrustedRoot(X509Certificate rootCertificate) throws CertificateException {
        Set<X509Certificate> trusted = trustedCertificates;
        if (trusted == null) {
            if (LOG.isDebugEnabled() && missingTrustedCertificatesWarningLogged.compareAndSet(false, true)) {
                LOG.debug("No trusted certificates configured, the root certificate is only verified with its own signature! Use setTrustedCertificates() to enable it.");
            }
            return;
        }

        if (!trusted.contains(rootCertificate)) {
            throw new CertificateException("Root certificate '" + rootCertificate.getSubjectX500Principal().getName() + "' is not trusted!");
        }
    }


    /**
     * Verify the validity dates of all certificates and that every issuer is a CA which is allowed to sign certificates.
     * A self-signed root of version 1 (no extensions) is accepted as issuer, as the JDK PKIX validation does for trust anchors.
     *
     * @param certs the certificate chain, the leaf first and the root last
     * @throws CertificateExpiredException if a certificate is expired
     * @throws CertificateNotYetValidException if a certificate is not yet valid
     * @throws CertificateException if an issuer is not a CA or not allowed to sign certificates
     */
    private void verifyChainConstraints(X509Certificate[] certs) throws CertificateException {
        for (int i = 0; i < certs.length; i++) {
            X509Certificate cert = certs[i];
            String subject = cert.getSubjectX500Principal().getName();
            try {
                cert.checkValidity();
            } catch (CertificateExpiredException e) {
                throw new CertificateExpiredException("Certificate '" + subject + "' is expired (not after " + cert.getNotAfter() + ")!");
            } catch (CertificateNotYetValidException e) {
                throw new CertificateNotYetValidException("Certificate '" + subject + "' is not yet valid (not before " + cert.getNotBefore() + ")!");
            }

            if (i == 0) {
                // the leaf is no issuer
                continue;
            }

            boolean isV1Root = i == certs.length - 1 && cert.getVersion() == 1;
            if (!isV1Root && cert.getBasicConstraints() < 0) {
                throw new CertificateException("Issuer certificate '" + subject + "' is not a CA (basic constraints)!");
            }

            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage != null && (keyUsage.length <= KEY_USAGE_KEY_CERT_SIGN || !keyUsage[KEY_USAGE_KEY_CERT_SIGN])) {
                throw new CertificateException("Issuer certificate '" + subject + "' is not allowed to sign certificates (key usage)!");
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Certificate chain validity dates, basic constraints and key usage checked successful.");
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

        PKIXParameters params = new PKIXParameters(Collections.singleton(trustAnchor));
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) validator.getRevocationChecker();
        // PREFER_CRLS: check the CRL Distribution Points first, fallback to OCSP (Authority Information Access).
        // A revoked certificate always fails. If the status can not be determined (no OCSP / CRL endpoint or not
        // reachable), the certificate is accepted with a warning (soft fail), or rejected in strict mode.
        if (revocationStrict) {
            revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS));
        } else {
            revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS, PKIXRevocationChecker.Option.SOFT_FAIL));
        }

        // disable the old built-in revocation mechanism (which requires a JVM-wide System.setProperty);
        // revocation is handled by the explicitly added PKIXRevocationChecker instead.
        params.setRevocationEnabled(false);
        params.addCertPathChecker(revocationChecker);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath certPath = cf.generateCertPath(Arrays.asList(Arrays.copyOf(certs, pathLength)));
        if (!revocationStrict) {
            // validate the path without revocation first: such errors must not be accepted as unknown revocation status
            PKIXParameters pathParams = new PKIXParameters(Collections.singleton(trustAnchor));
            pathParams.setRevocationEnabled(false);
            validator.validate(certPath, pathParams);
        }

        try {
            validator.validate(certPath, params);
        } catch (CertPathValidatorException e) {
            // the JDK soft fail only covers network errors; a certificate without any OCSP / CRL endpoint fails with
            // an unspecific reason. In the default (not strict) mode only a revoked certificate is rejected.
            if (revocationStrict || e.getReason() == CertPathValidatorException.BasicReason.REVOKED) {
                throw e;
            }

            LOG.warn("Certificate revocation status could not be determined, certificate accepted: " + e.getMessage());
            if (consumer != null) {
                consumer.accept("Certificate revocation status could not be determined.");
            }
            return;
        }

        List<CertPathValidatorException> softFailExceptions = revocationChecker.getSoftFailExceptions();
        if (softFailExceptions != null && !softFailExceptions.isEmpty()) {
            for (CertPathValidatorException e : softFailExceptions) {
                LOG.warn("Certificate revocation status could not be determined, certificate accepted (soft fail): " + e.getMessage());
            }

            if (consumer != null) {
                consumer.accept("Certificate revocation status could not be determined (soft fail).");
            }
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Certificate revocation check passed.");
        }
        if (consumer != null) {
            consumer.accept("Certificate revocation check passed.");
        }
    }
}
