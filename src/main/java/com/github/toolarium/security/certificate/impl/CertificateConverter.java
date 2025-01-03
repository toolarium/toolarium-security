/*
 * CertificateConverter.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.impl;

import com.github.toolarium.common.util.FileUtil;
import com.github.toolarium.security.certificate.ICertificateConverter;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;


/**
 * Implements the {@link ICertificateConverter}.
 * 
 * @author patrick
 */
public class CertificateConverter implements ICertificateConverter {
    
    /** the public key certificate start */
    public static final String PUBLIC_CERTIFICATE_START = "-----BEGIN CERTIFICATE-----";

    /** the public key certificate end */
    public static final String PUBLIC_CERTIFICATE_END = "-----END CERTIFICATE-----";
    private static final String NL = "\n";
    

    /**
     * @see com.github.toolarium.security.certificate.ICertificateConverter#getX509Certificates(java.io.File)
     */
    @Override
    public X509Certificate[] getX509Certificates(File file) throws GeneralSecurityException, IOException {
        if (file == null) {
            return null;
        }
        
        return getX509Certificates(FileUtil.getInstance().readFileContent(file));
    }



    /**
     * @see com.github.toolarium.security.certificate.ICertificateConverter#getX509Certificates(java.lang.String)
     */
    @Override
    public X509Certificate[] getX509Certificates(String content) throws GeneralSecurityException {
        if (content == null || content.length() == 0) {
            return null;
        }
        
        // replace all spaces with newline
        String data = content.trim().replaceAll(" ", NL).replaceAll("\nCERTIFICATE", " CERTIFICATE");
        String formatedCertificate = formatPKCS7(data);
        ArrayList<X509Certificate> certificates = new ArrayList<X509Certificate>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream bais = new ByteArrayInputStream(formatedCertificate.getBytes());

        X509Certificate cert = null;
        while (bais.available() > 0) {
            cert = (X509Certificate) cf.generateCertificate(bais);
            certificates.add(cert);
            // logCertificate( Level.DEBUG, cert );
        }

        X509Certificate[] certs = new X509Certificate[certificates.size()];
        for (int i = 0; i < certs.length; i++) {
            certs[i] = certificates.get(i);
        }

        return certs;
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateConverter#combineCertificates(java.security.cert.X509Certificate[], java.security.cert.X509Certificate[])
     */
    @Override
    public X509Certificate[] combineCertificates(X509Certificate[] certs, X509Certificate[] caCerts) {
        X509Certificate[] combinedCerts = null;
        int len = 0;
        int offset = 0;

        if (certs != null) {
            len += certs.length;
        }
        
        if (caCerts != null) {
            len += caCerts.length;
        }
        
        if (len > 0) {
            combinedCerts = new X509Certificate[len];
        } else {
            return null;
        }
        
        if (certs != null) {
            for (int i = 0; i < certs.length; i++) {
                combinedCerts[offset++] = certs[i];
            }
        }

        if (caCerts != null) {
            for (int i = 0; i < caCerts.length; i++) {
                combinedCerts[offset++] = caCerts[i];
            }
        }

        return combinedCerts;
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateConverter#formatPKCS7(java.lang.String)
     */
    @Override
    public String formatPKCS7(String rawCertificate) {
        return PKIUtil.getInstance().formatBuffer(rawCertificate, 64, PUBLIC_CERTIFICATE_START, PUBLIC_CERTIFICATE_END);
    }

    
    /**
     * @see com.github.toolarium.security.certificate.ICertificateConverter#formatPKCS7(java.security.cert.Certificate)
     */
    @Override
    public String formatPKCS7(Certificate certificate) throws CertificateEncodingException {
        if (certificate == null) {
            return null;
        }

        return formatPKCS7(new String(Base64.getEncoder().encode(certificate.getEncoded())));
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateConverter#formatPKCS7(java.security.cert.X509Certificate[])
     */
    @Override
    public String formatPKCS7(X509Certificate[] certificateChain) throws CertificateEncodingException {
        String certificateChainContent = "";

        for (int i = 0; i < certificateChain.length; i++) {
            if (i > 0) {
                certificateChainContent += NL;
            }
            
            String cert = formatPKCS7(certificateChain[i]);
            if (cert != null) {
                certificateChainContent += cert;
            }
        }

        return certificateChainContent;
    }
}
