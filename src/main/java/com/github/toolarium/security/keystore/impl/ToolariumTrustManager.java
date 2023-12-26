/*
 * ToolariumTrustManager.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.impl;

import com.github.toolarium.common.stacktrace.StackTrace;
import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import javax.net.ssl.TrustManager;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Toolariun {@link TrustManager} which logs the verification.
 *  
 * @author patrick
 */
public class ToolariumTrustManager implements javax.net.ssl.X509TrustManager {
    private static final Logger LOG = LoggerFactory.getLogger(ToolariumTrustManager.class);
    private static final int CERT_NOT_CHECKED = 0;
    private static final int CERT_CHECKFAILED = 1;
    private static final int CERT_INVALIDSIGNATURE = 2;
    private static final int CERT_CERTEXPIRED = 3;
    private static final int CERT_CAEXPIRED = 4;
    private static final int CERT_UNKNOWNCA = 5;
    private static final int CERT_INVALIDCOMMONNAME = 6;
    
    private HashMap<String, X509Certificate> trustedCerts;
    private int certCheckResult;
    private boolean verifyCertificate;

    
    /**
     * Constructor for ToolariumTrustManager
     */
    public ToolariumTrustManager() {
        trustedCerts = new HashMap<String, X509Certificate>();
        certCheckResult = CERT_NOT_CHECKED;
        verifyCertificate = true;
    }
    

    /**
     * Adds a trusted certificate
     * 
     * @param cert the certificate to trust
     */
    public void addTrustedCertificate(X509Certificate cert) {
        if (cert == null) {
            return;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding trust certificate: " + cert.getIssuerX500Principal());
        }

        String caDN = cert.getIssuerX500Principal().getName();
        trustedCerts.put(caDN, cert);
    }
    

    /**
     * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String protocol) throws CertificateException {
        if (chain.length == 0) {
            LOG.warn("The received client certificate was empty!");
            return;
        }

        verifyCertificateChain(chain, protocol);
    }

    
    /**
     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String)
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String protocol) throws CertificateException {
        if (chain.length == 0) {
            LOG.warn("The received server certificate was empty!");
            return;
        }

        // check if the server certificate should be added or not
        for (int i = 0; i < chain.length; i++) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Server certificate #" + (i + 1) + ": \n" + CertificateUtilFactory.getInstance().getConverter().formatPKCS7(chain[i]));
            }
            
            if (trustServerCertificate(chain[i])) {
                addTrustedCertificate(chain[i]);
            }
        }

        if (verifyCertificate) {
            verifyCertificateChain(chain, protocol);
        }
    }    

    
    /**
     * Set the verify certificate
     *
     * @param verifyCertificate true to verify certificates
     */
    public void setVerifyCertificate(boolean verifyCertificate) {
        this.verifyCertificate = verifyCertificate;
    }
    
    
    /**
     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];                    
    }
    
    
    /**
     * Gets the check result
     * @return the check result
     */
    public int getCheckResult() {
        return certCheckResult;
    }        
    
    
    /**
     * Verifies a certificate chain.
     * 
     * @param chain a certificate chain
     * @param protocol the protocol
     * @throws CertificateException in case of error
     */
    public void verifyCertificateChain(X509Certificate[] chain, String protocol) throws CertificateException {
        certCheckResult = CERT_NOT_CHECKED;
        int len = chain.length;
        if (len == 0) {
            return;
        }

        checkCertificateChain(chain);
        
        LOG.info("Check client " + protocol + " certificate(s)...");
        if (LOG.isDebugEnabled()) {
            PKIUtil.getInstance().processCertificate(LOG::debug, null, chain);
        }

        // The first certificate in the chain, chain[0] is the subject certificate of the server.
        X509Certificate subjectcert = chain[0];
        
        // Retrieve the Common Name 'CN' for which the Server Certificate has been issued.
        String commonName = subjectcert.getSubjectX500Principal().getName();
        if (commonName == null) {
            certCheckResult = CERT_CHECKFAILED;
            StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Fatal Error on Server Certificate Verification: ", 3);
            throw new CertificateException("Fatal Error on Server Certificate Verification!");
        }
        
        String server = getHostname();
        if (server != null && server.length() > 0) {
            try {
                X500Principal principal = subjectcert.getSubjectX500Principal();
                X500Name x500name = new X500Name(principal.getName());
                RDN cn = x500name.getRDNs(BCStyle.CN)[0];
                String name = IETFUtils.valueToString(cn.getFirst().getValue());

                // The Common Name 'CN' for which the Server Certificate has been issued has to match the Server we want to contact
                if (!server.equalsIgnoreCase(name)) {
                    StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Common Name of Certificate different from Servername on Server Certificate Verification ([" + server + "] != [" + name + "]): ", 3);
                    certCheckResult = CERT_INVALIDCOMMONNAME;
                    throw new CertificateException("Common Name of Certificate different from Servername on Server Certificate Verification");
                }
            } catch (RuntimeException e) {
                StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Invalid common name (" + commonName + "): ", 3);
                certCheckResult = CERT_INVALIDCOMMONNAME;
                throw new CertificateException("Invalid common name: " + commonName + ": " + e.getMessage());
            }
        }

        checkCertificate(subjectcert);

        if (chain.length > 1) {
            // get the CA which signed the Server Certificate
            for (int i = 1; i < chain.length; i++) {
                X509Certificate c = chain[i];

                String caDN = c.getIssuerX500Principal().getName();
                X509Certificate cacert = trustedCerts.get(caDN);
                if ((cacert == null) || !(c.equals(cacert))) {
                    certCheckResult = CERT_UNKNOWNCA;
                    StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Unknown CA, Server Certificate Verification: ", 3);
                    throw new CertificateException("Unknown CA, Server Certificate Verification!");
                }

                checkCACertificate(c);
                checkCACertificate(cacert);
            }
        }
        
        LOG.info("Checked successful client " + protocol + " certificate(s).");
    }
        
    
    /**
     * Checks the certificate
     * 
     * @param cert the certificate to test
     * @throws CertificateException In case of a certificate error
     */
    protected void checkCertificate(X509Certificate cert) throws CertificateException {
        String dn = cert.getIssuerX500Principal().getName();
        X509Certificate c = trustedCerts.get(dn);
        if ((c == null) || !(cert.equals(c))) {
            certCheckResult = CERT_UNKNOWNCA;
            StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Unknown CA, Server Certificate Verification: ", 3);
                
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unknown CA, Server Certificate for '" + dn + "':\n" + CertificateUtilFactory.getInstance().getConverter().formatPKCS7(cert));
            }

            throw new CertificateException("Unknown CA, Server Certificate Verification!");
        }
        
        try {
            // verify that the subject certificate is valid
            cert.checkValidity();
        } catch (CertificateExpiredException ex) {
            certCheckResult = CERT_CERTEXPIRED;
            StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Certificate Expired on Server Certificate Verification: ", 3);
            throw new CertificateException("Certificate Expired on Server Certificate Verification!");
        } catch (CertificateNotYetValidException ex) {
            certCheckResult = CERT_CERTEXPIRED;
            StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Certificate Expired on Server Certificate Verification: ", 3);
            throw new CertificateException("Certificate Expired on Server Certificate Verification!");
        } catch (Exception ex) {
            certCheckResult = CERT_CHECKFAILED;
            StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Fatal Error on Server Certificate Verification: ", 3);
            throw new CertificateException("Fatal Error on Server Certificate Verification!");
        }
    }


    /**
     * Checks the CA certificate
     * 
     * @param cacert the certificate to test
     * @throws CertificateException In case of a certificate error
     */
    protected void checkCACertificate(X509Certificate cacert) throws CertificateException {
        // verify that the CA certificate is valid
        try {
            cacert.checkValidity();
        } catch (CertificateExpiredException ex) {
            certCheckResult = CERT_CAEXPIRED;
            StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "CA Certificate Expired on Server Certificate Verification: ", 3);
            throw new CertificateException("CA Certificate Expired on Server Certificate Verification!");
        } catch (CertificateNotYetValidException ex) {
            certCheckResult = CERT_CAEXPIRED;
            StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "CA Certificate Expired on Server Certificate Verification: ", 3);
            throw new CertificateException("CA Certificate Expired on Server Certificate Verification");
        } catch (Exception ex) {
            certCheckResult = CERT_CHECKFAILED;
            StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Fatal Error on Server Certificate Verification: ", 3);
            throw new CertificateException("Fatal Error on Server Certificate Verification!");
        }
    }

    
    /**
     * Checks the certificate chain
     * 
     * @param chain the chain
     * @throws CertificateException In case of a certificate error
     */
    protected void checkCertificateChain(X509Certificate[] chain) throws CertificateException {
        try {
            // verify that the subject certificate has been properly signed by the issuer
            CertificateUtilFactory.getInstance().getVerifier().verifyCertificateChain(LOG::debug, chain);
        } catch (SignatureException ex) {
            certCheckResult = CERT_INVALIDSIGNATURE;
            StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Certificate Expired on Server Certificate Verification: ", 3);
            throw new CertificateException("Invalid Signature Error on Server Certificate Verification!");
        } catch (CertificateExpiredException ex) {
            certCheckResult = CERT_CERTEXPIRED;
            StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Certificate Expired on Server Certificate Verification: ", 3);
            throw new CertificateException("Certificate Expired on Server Certificate Verification!");
        } catch (CertificateNotYetValidException ex) {
            certCheckResult = CERT_CERTEXPIRED;
            StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Certificate Expired on Server Certificate Verification: ", 3);
            throw new CertificateException("Certificate Expired on Server Certificate Verification!");
        } catch (Exception ex) {
            certCheckResult = CERT_CHECKFAILED;
            StackTrace.processStackTrace(LOG::warn, StackTrace.DEFAULT_EXCLUDES, "Fatal Error on Server Certificate Verification: ", 3);
            throw new CertificateException("Fatal Error on Server Certificate Verification!");
        }
    }

    
    /**
     * Check if the given certificate should be trust and added to the certificate server list
     * 
     * @param certificate the server certificate
     * @return true if we trust the server certificate
     */
    protected boolean trustServerCertificate(X509Certificate certificate) {
        return true;
    }    
    
    
    /**
     * Gets the host name 
     * 
     * @return the name
     */
    protected String getHostname() {
        return null;
    }
}
