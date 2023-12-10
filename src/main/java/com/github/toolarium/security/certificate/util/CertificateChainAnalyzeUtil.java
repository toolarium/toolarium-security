/*
 * CertificateChainAnalyzeUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.util;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Util class to support the certificate chain.
 *  
 * @author patrick
 */
public final class CertificateChainAnalyzeUtil {
    private static final Logger LOG = LoggerFactory.getLogger(CertificateChainAnalyzeUtil.class);
    private static final boolean ALLOW_LOG_SELF_SIGN_TESTS = false;


    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final CertificateChainAnalyzeUtil INSTANCE = new CertificateChainAnalyzeUtil();
    }

    
    /**
     * Constructor
     */
    private CertificateChainAnalyzeUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static CertificateChainAnalyzeUtil getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Build chain for
     *
     * @param keypair the key pair
     * @param certs the certificates
     * @return the certificates
     */
    public List<X509Certificate> buildChainFor(KeyPair keypair, Collection<X509Certificate> certs) {
        return buildChainFor(keypair.getPublic(), certs);
    }


    /**
     * Build chain for 
     *
     * @param key the public key
     * @param certs the certificates
     * @return the certificates
     * @throws IllegalArgumentException if the chain is null or empty
     * @throws IllegalStateException In case of a validation error
     */
    public List<X509Certificate> buildChainFor(PublicKey key, Collection<X509Certificate> certs) throws IllegalArgumentException, IllegalStateException {
        final List<X509Certificate> chain = new ArrayList<X509Certificate>(certs.size());

        final X509Certificate subject = getCertificateFor(key, certs);
        if (subject == null) {
            throw new IllegalArgumentException("Cannot find X509Certificate which corresponds to " + key);
        }
        
        chain.add(subject);

        // Keep going until we find a root certificate (or until the chain can't be continued)
        X509Certificate old = null;
        X509Certificate current = subject;
        while (current != null && (old == null || !old.equals(current)) && !isSelfSigned(current)) {
            old = current;
            current = getIssuer(current, certs);

            if (current != null) {
                chain.add(current);
            } else {
                LOG.warn("Building chain for " + certs.size() + " cert[s] but had to stop after " + chain.size() + " because I could not find the issuer for " + old.getSubjectX500Principal());
                throw new IllegalArgumentException("Could not determine issuer for certificate: " + old.getSubjectX500Principal() + ". Please ensure certificate list contains all certificates back to the CA's self-signed root!");
            }

            if (chain.size() > certs.size()) {
                LOG.warn("Too many certificates in chain. Chain: " + Arrays.toString(getPrincipals(chain)) + ", Source: " + Arrays.toString(getPrincipals(new ArrayList<X509Certificate>(certs))));
                throw new IllegalStateException("Chain build failed: too many certs in chain (greater than number of input certs)! Chain: " + Arrays.toString(getPrincipals(chain)));
            }
        }

        // Normalise the array
        return normaliseChain(chain);
    }

    
    /**
     * Get certificate for
     *
     * @param publicKey the public key
     * @param certs the certificates
     * @return the corresponding certificate
     */
    public X509Certificate getCertificateFor(PublicKey publicKey, Collection<X509Certificate> certs) {
        // Search through the certs until we find the public key we're looking for
        for (X509Certificate cert : certs) {
            if (cert.getPublicKey().equals(publicKey)) {
                return cert;
            }
        }

        return null;
    }

    
    /**
     * Determines if a certificate is a self signed certificate
     *
     * @param certificate the certificate to test
     * @return true if the certificate is self-signed, otherwise false if the certificate was not self-signed or the certificate signature could not be verified
     */
    public boolean isSelfSigned(X509Certificate certificate) {
        return isSignedBy(certificate, certificate.getPublicKey());
    }
    
    

    /**
     * Determines if a certificate is signed by the public key
     *
     * @param certificate the certificate to test
     * @param signer the signer to test
     * @return true if the certificate is signed, otherwise false if the certificate was not signed or the certificate signature could not be verified
     */
    @SuppressWarnings("unused")
    public boolean isSignedBy(X509Certificate certificate, PublicKey signer) {
        try {
            certificate.verify(signer);

            // if verify does not throw an exception then it's a self-signed certificate
            return true;
        } catch (Exception e) {
            if (ALLOW_LOG_SELF_SIGN_TESTS && LOG.isDebugEnabled()) {
                final String dn = certificate.getIssuerX500Principal().getName();
                String msg = "Signing issue, the [" + dn + "] not signed by [" + signer + "]:" + e.getMessage();
                //LOG.debug("Signing issue, the [" + dn + "] not signed by [" + signer + "]:" + e.getMessage(), e);

                if (LOG.isDebugEnabled()) {
                    PKIUtil.getInstance().processPublicKeyInfo(LOG::debug, msg, signer);
                    PKIUtil.getInstance().processCertificate(LOG::debug, msg, certificate);
                }
            }

            return false;
        }
    }

    
    /**
     * Get the issues
     *
     * @param subject the subject
     * @param certs the cerificates
     * @return the certificate
     */
    public X509Certificate getIssuer(X509Certificate subject, Collection<X509Certificate> certs) {
        for (X509Certificate cert : certs) {
            if (cert.getSubjectX500Principal().equals(subject.getIssuerX500Principal())) {
                if (isSignedBy(subject, cert.getPublicKey())) {
                    return cert;
                }
            }
        }

        return null;
    }

    
    /**
     * Get the principals 
     *
     * @param chain the chain
     * @return the principal
     * @throws IllegalArgumentException if the chain is null or empty
     */
    public X500Principal[] getPrincipals(List<X509Certificate> chain) {
        if (chain.contains(null)) {
            throw new IllegalArgumentException("Certificate chain contains null!");
        }
        
        X500Principal[] array = new X500Principal[chain.size()];
        for (int i = 0; i < array.length; i++) {
            array[i] = chain.get(i).getSubjectX500Principal();
        }
        
        return array;
    }

    
    /**
     * Take a chain and return a (Read-only) chain with the root certificate as the first entry
     *
     * @param chain a chain with the certificates in order (either leading away from root or leading towards root)
     * @return a read-only chain leading away from the root certificate
     * @throws IllegalArgumentException if the chain is null or empty
     */
    public List<X509Certificate> normaliseChain(List<X509Certificate> chain) {
        return toRootFirst(chain);
    }

    
    /**
     * Take a chain and return a (Read-only) chain with the root certificate as the first entry
     *
     * @param chain a chain with the certificates in order (either leading away from root or leading towards root)
     * @return a read-only chain leading away from the root certificate
     * @throws IllegalArgumentException if the chain is null or empty
     */
    public List<X509Certificate> toRootFirst(List<X509Certificate> chain) {
        if (chain == null || chain.isEmpty()) {
            throw new IllegalArgumentException("Must provide a chain that is non-null and non-empty");
        }
        
        final List<X509Certificate> out;
        // Sort the list so the root certificate comes first
        if (!isSelfSigned(chain.get(0))) {
            // Copy the chain List so we can modify it
            out = new ArrayList<X509Certificate>(chain);

            Collections.reverse(out);

            // If, even when reversed, the chain doesn't have a root at the start then the chain's invalid
            if (!isSelfSigned(out.get(0))) {
                throw new IllegalArgumentException("Neither end of the certificate chain has a Root! " + chain);
            }
        } else {
            out = chain;
        }

        return Collections.unmodifiableList(out);
    }
}