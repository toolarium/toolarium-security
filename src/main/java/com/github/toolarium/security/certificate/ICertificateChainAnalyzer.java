/*
 * ICertificateChainAnalyzer.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import javax.security.auth.x500.X500Principal;


/**
 * Defines the certificate chain analyser
 *  
 * @author patrick
 */
public interface ICertificateChainAnalyzer {
    
    /**
     * Build chain for
     *
     * @param keypair the key pair
     * @param certs the certificates
     * @return the certificates
     */
    List<X509Certificate> buildChainFor(KeyPair keypair, Collection<X509Certificate> certs);


    /**
     * Build chain for 
     *
     * @param key the public key
     * @param certs the certificates
     * @return the certificates
     * @throws IllegalArgumentException if the chain is null or empty
     * @throws IllegalStateException In case of a validation error
     */
    List<X509Certificate> buildChainFor(PublicKey key, Collection<X509Certificate> certs) throws IllegalArgumentException, IllegalStateException;
    
    
    /**
     * Get certificate for
     *
     * @param publicKey the public key
     * @param certs the certificates
     * @return the corresponding certificate
     */
    X509Certificate getCertificateFor(PublicKey publicKey, Collection<X509Certificate> certs);
    
    
    /**
     * Determines if a certificate is a self-signed certificate
     *
     * @param certificate the certificate to test
     * @return true if the certificate is self-signed, otherwise false if the certificate was not self-signed or the certificate signature could not be verified
     */
    boolean isSelfSigned(X509Certificate certificate);
        

    /**
     * Determines if a certificate is signed by the public key
     *
     * @param certificate the certificate to test
     * @param signer the signer to test
     * @return true if the certificate is signed, otherwise false if the certificate was not signed or the certificate signature could not be verified
     */
    boolean isSignedBy(X509Certificate certificate, PublicKey signer);
    
    
    /**
     * Get the issues
     *
     * @param subject the subject
     * @param certs the cerificates
     * @return the certificate
     */
    X509Certificate getIssuer(X509Certificate subject, Collection<X509Certificate> certs);
    
    
    /**
     * Get the principals 
     *
     * @param chain the chain
     * @return the principal
     * @throws IllegalArgumentException if the chain is null or empty
     */
    X500Principal[] getPrincipals(List<X509Certificate> chain);

    
    /**
     * Take a chain and return a (Read-only) chain with the root certificate as the first entry
     *
     * @param chain a chain with the certificates in order (either leading away from root or leading towards root)
     * @return a read-only chain leading away from the root certificate
     * @throws IllegalArgumentException if the chain is null or empty
     */
    List<X509Certificate> normaliseChain(List<X509Certificate> chain);

    
    /**
     * Take a chain and return a (Read-only) chain with the root certificate as the first entry
     *
     * @param chain a chain with the certificates in order (either leading away from root or leading towards root)
     * @return a read-only chain leading away from the root certificate
     * @throws IllegalArgumentException if the chain is null or empty
     */
    List<X509Certificate> toRootFirst(List<X509Certificate> chain);
}
