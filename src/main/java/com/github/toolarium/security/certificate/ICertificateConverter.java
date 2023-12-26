/*
 * ICertificateConverter.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;


/**
 * Defines the certificate converter interface.
 *  
 * @author patrick
 */
public interface ICertificateConverter {
    
    /**
     * Reads a PKCS#7 (with base64 encoded) X509 certificates from a file, which are each bounded at the beginning by
     * <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     *
     * @param file the file to read
     * @return the read certificates
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of error
     */
    X509Certificate[] getX509Certificates(File file) throws GeneralSecurityException, IOException;

    
    /**
     * Read a PKCS#7 (with base64 encoded) X509 certificates from the given buffer, which are each bounded at the beginning by
     * <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     *
     * @param content the content
     * @return the read certificates
     * @throws GeneralSecurityException in case of error
     */
    X509Certificate[] getX509Certificates(String content) throws GeneralSecurityException;
    
    
    /**
     * Combine two certificate arrays
     *
     * @param certs the certificate
     * @param caCerts the ca certificate(s)
     * @return the combined certificates
     */
    X509Certificate[] combineCertificates(X509Certificate[] certs, X509Certificate[] caCerts);
    
    
    /**
     * Formats a raw base64 encoded X509 certificates to a well formated X509 certificate (PEM format), which are each bounded at the beginning by
     * <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     *
     * @param content the raw certificate to format
     * @return the well formed certificate
     */
    String formatPKCS7(String content);
    
    
    /**
     * Create certificate chain into a well formed string representation
     *
     * @param certificateChain the certificate chain
     * @return the string representation
     * @throws CertificateEncodingException In case of a certificate error
     */
    String formatPKCS7(X509Certificate[] certificateChain) throws CertificateEncodingException;

    
    /**
     * Formats a certificate to a well formated X509 certificate (PEM format), which are each bounded at the beginning by
     * <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     *
     * @param certificate the certificate to format in PEM format
     * @return the well formed certificate
     * @throws CertificateEncodingException In case of a certificate error
     */
    String formatPKCS7(Certificate certificate) throws CertificateEncodingException;
}
