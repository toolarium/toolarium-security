/*
 * CertificateVerifier.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.impl;

import com.github.toolarium.security.certificate.ICertificateVerifier;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
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
        
        LOG.debug("Certificate chain checked successful!");
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateVerifier#verifyCertificate(java.util.function.Consumer, java.security.cert.X509Certificate, java.security.cert.X509Certificate)
     */
    @Override
    public void verifyCertificate(Consumer<String> consumer, X509Certificate userCert, X509Certificate caCert) throws GeneralSecurityException {
        if (caCert != null) {
            LOG.debug("Verify certificate: '" + userCert.getSubjectX500Principal().getName() + "'"); // getSubjectDN()
            userCert.verify(caCert.getPublicKey());

            LOG.debug("Successfully verified CA certificate with public key.");
            if (consumer != null) {
                PKIUtil.getInstance().processPublicKeyInfo(consumer, null, caCert.getPublicKey());
            }
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
        
        LOG.debug("Verify certificate: '" + userCertificate.getSubjectX500Principal().getName() + "'"); // getSubjectDN
        userCertificate.verify(userCertificate.getPublicKey());

        LOG.debug("Successfully verified CA certificate with its own public key.");
        if (consumer != null) {
            PKIUtil.getInstance().processPublicKeyInfo(consumer, null, userCertificate.getPublicKey());
        }
    }

    

}
