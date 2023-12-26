/*
 * ICertificateVerifier.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.function.Consumer;


/**
 * Defines the certificate verifier interface.
 * 
 * @author patrick
 */
public interface ICertificateVerifier {
    
    /**
     * Verifies a chain of certificates where the user certificate is stored at index 0. The self-signed top level certificate is verified using its inherent
     * public key. Any other certificate of the chain is verified by means of the public key derived from the issuing certificate which is located
     * one index higher in the chain.
     * certs[0] = user certificate.
     * certs[x] = self signed CA certificate
     *
     * @param consumer the consumer
     * @param certs the certificate chain to verify
     * @throws GeneralSecurityException in case of error
     */
    void verifyCertificateChain(Consumer<String> consumer, X509Certificate[] certs) throws GeneralSecurityException;

    
    /**
     * Verifies the digital signature of a certificate.
     *
     * @param consumer the consumer
     * @param userCert the certificate to verify
     * @param caCert the certificate of the CA which has issued the userCert or <code>null</code> if the userCert is a self signed certificate
     * @throws GeneralSecurityException in case of error
     */
    void verifyCertificate(Consumer<String> consumer, X509Certificate userCert, X509Certificate caCert) throws GeneralSecurityException;
    
    
    /**
     * Verifies the digital signature of a certificate.
     *
     * @param consumer the consumer
     * @param userCertificate the certificate to verify
     * @throws GeneralSecurityException in case of error
     */
    void verifyCertificate(Consumer<String> consumer, X509Certificate userCertificate) throws GeneralSecurityException;
}
