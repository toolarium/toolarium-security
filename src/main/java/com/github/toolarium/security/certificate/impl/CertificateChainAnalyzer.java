/*
 * CertificateChainAnalyzer.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.impl;

import com.github.toolarium.security.certificate.ICertificateChainAnalyzer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SignatureException;
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
 * Implements the {@link ICertificateChainAnalyzer}.
 *  
 * @author patrick
 */
public class CertificateChainAnalyzer implements ICertificateChainAnalyzer {
    private static final Logger LOG = LoggerFactory.getLogger(CertificateChainAnalyzer.class);
    private static final boolean ALLOW_LOG_SELF_SIGN_TESTS = false;

    
    /**
     * Constructor for CertificateChainAnalyzer
     */
    public CertificateChainAnalyzer() {
        // NOP
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateChainAnalyzer#buildChainFor(java.security.KeyPair, java.util.Collection)
     */
    @Override
    public List<X509Certificate> buildChainFor(KeyPair keypair, Collection<X509Certificate> certs) {
        return buildChainFor(keypair.getPublic(), certs);
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateChainAnalyzer#buildChainFor(java.security.PublicKey, java.util.Collection)
     */
    @Override
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
                LOG.warn("Building chain for {} cert[s] but had to stop after {} because I could not find the issuer for {}", certs.size(), chain.size(), old.getSubjectX500Principal());
                throw new IllegalArgumentException("Could not determine issuer for certificate: " + old.getSubjectX500Principal() + ". Please ensure certificate list contains all certificates back to the CA's self-signed root!");
            }

            if (chain.size() > certs.size()) {
                LOG.warn("Too many certificates in chain. Chain: {}, Source: {}", Arrays.toString(getPrincipals(chain)), Arrays.toString(getPrincipals(new ArrayList<X509Certificate>(certs))));
                throw new IllegalStateException("Chain build failed: too many certs in chain (greater than number of input certs)! Chain: " + Arrays.toString(getPrincipals(chain)));
            }
        }

        // Normalise the array: the chain leads towards the root and its last certificate is already verified as
        // self-signed, so the signatures are not verified again
        if (chain.size() == 1) {
            return Collections.unmodifiableList(chain);
        }
        return reverse(chain);
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateChainAnalyzer#getCertificateFor(java.security.PublicKey, java.util.Collection)
     */
    @Override
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
     * @see com.github.toolarium.security.certificate.ICertificateChainAnalyzer#isSelfSigned(java.security.cert.X509Certificate)
     */
    @Override
    public boolean isSelfSigned(X509Certificate certificate) {
        // a self-signed certificate is self-issued: compare the names before the expensive signature verification
        if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }

        return isSignedBy(certificate, certificate.getPublicKey());
    }
    
    

    /**
     * @see com.github.toolarium.security.certificate.ICertificateChainAnalyzer#isSignedBy(java.security.cert.X509Certificate, java.security.PublicKey)
     */
    @Override
    @SuppressWarnings("unused")
    public boolean isSignedBy(X509Certificate certificate, PublicKey signer) {
        try {
            certificate.verify(signer);

            // if verify does not throw an exception then it's a self-signed certificate
            return true;
        } catch (SignatureException | InvalidKeyException e) {
            if (ALLOW_LOG_SELF_SIGN_TESTS && LOG.isDebugEnabled()) {
                final String dn = certificate.getIssuerX500Principal().getName();
                String msg = "Signing issue, the [" + dn + "] not signed by [" + signer + "]:" + e.getMessage();
                //LOG.debug("Signing issue, the [" + dn + "] not signed by [" + signer + "]:" + e.getMessage(), e);

                if (LOG.isDebugEnabled()) {
                    com.github.toolarium.security.pki.util.PKIUtil.getInstance().processPublicKeyInfo(LOG::debug, msg, signer);
                    com.github.toolarium.security.pki.util.PKIUtil.getInstance().processCertificate(LOG::debug, msg, certificate);
                }
            }

            return false;
        } catch (GeneralSecurityException e) {
            // not a signature mismatch but e.g. a missing algorithm or provider: the signature could not be verified
            LOG.warn("Could not verify the signature of certificate '{}': {}", certificate.getSubjectX500Principal().getName(), e.toString());
            return false;
        }
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateChainAnalyzer#getIssuer(java.security.cert.X509Certificate, java.util.Collection)
     */
    @Override
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
     * @see com.github.toolarium.security.certificate.ICertificateChainAnalyzer#getPrincipals(java.util.List)
     */
    @Override
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
     * @see com.github.toolarium.security.certificate.ICertificateChainAnalyzer#normaliseChain(java.util.List)
     */
    @Override
    public List<X509Certificate> normaliseChain(List<X509Certificate> chain) {
        return toRootFirst(chain);
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateChainAnalyzer#toRootFirst(java.util.List)
     * @param chain a chain with the certificates in order (either leading away from root or leading towards root)
     * @return a read-only chain leading away from the root certificate
     * @throws IllegalArgumentException if the chain is null or empty
     */
    public List<X509Certificate> toRootFirst(List<X509Certificate> chain) {
        if (chain == null || chain.isEmpty()) {
            throw new IllegalArgumentException("Must provide a chain that is non-null and non-empty");
        }
        
        // Sort the list so the root certificate comes first
        if (isSelfSigned(chain.get(0))) {
            return Collections.unmodifiableList(chain);
        }

        // If, even when reversed, the chain doesn't have a root at the start then the chain's invalid;
        // a chain with one certificate is already checked
        if (chain.size() == 1 || !isSelfSigned(chain.get(chain.size() - 1))) {
            throw new IllegalArgumentException("Neither end of the certificate chain has a Root! " + Arrays.toString(getPrincipals(chain)));
        }

        return reverse(chain);
    }


    /**
     * Reverse the order of a chain.
     *
     * @param chain the chain
     * @return a read-only reversed copy of the chain
     */
    private List<X509Certificate> reverse(List<X509Certificate> chain) {
        // Copy the chain List so we can modify it
        final List<X509Certificate> out = new ArrayList<X509Certificate>(chain);
        Collections.reverse(out);
        return Collections.unmodifiableList(out);
    }
}
