/*
 * IKeyConverter.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;


/**
 * Defines the key converter interface.
 * 
 * @author patrick
 */
public interface IKeyConverter {

    /**
     * Get the provider
     *
     * @return the provider or null
     */
    String getProvider();


    /**
     * Get the type, e.g. RSA, DSA or EC
     *
     * @return the type as string
     */
    String getType();
    
    
    /**
     * Generates a KeyPair containing a Private- and PublicKey
     * 
     * @return the created KeyPair
     * @throws GeneralSecurityException in case of error
     */
    KeyPair generateKeyPair() throws GeneralSecurityException;

    
    /**
     * Generates a KeyPair containing a Private- and PublicKey
     * 
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param keySize the size of the key
     * @return the created KeyPair
     * @throws GeneralSecurityException in case of error
     */
    KeyPair generateKeyPair(String algorithm, int keySize) throws GeneralSecurityException;

    
    /**
     * Reads PKCS#8 formated public key from a file, which are each bounded at the beginning by
     * <code>-----BEGIN ... PUBLIC KEY-----</code>, and bounded at the end by <code>-----END ... PUBLIC KEY-----</code>.
     * 
     * @param file the file to read
     * @return the private key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    PublicKey getPublicKey(File file) throws IOException, GeneralSecurityException;

    
    /**
     * Reads PKCS#8 formated public key from a buffer, which are each bounded at the beginning by
     * <code>-----BEGIN ... PUBLIC KEY-----</code>, and bounded at the end by <code>-----END ... PUBLIC KEY-----</code>.
     * @param buffer the data
     * @return the public key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    PublicKey getPublicKey(byte[] buffer) throws IOException, GeneralSecurityException;

    
    /**
     * Reads PKCS#8 formated public key from a buffer which are each bounded at the beginning by
     * <code>-----BEGIN PUBLIC KEY-----</code>, and bounded at the end by <code>-----END PUBLIC KEY-----</code>.
     * 
     * @param content the content
     * @return the public key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    PublicKey getPublicKey(String content) throws IOException, GeneralSecurityException;

    
    /**
     * Reads PKCS#8 formated private key from a file, which are each bounded at the beginning by
     * <code>-----BEGIN ... PRIVATE KEY-----</code>, and bounded at the end by <code>-----END ... PRIVATE KEY-----</code>.
     * 
     * @param file the file to read
     * @return the private key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    PrivateKey getPrivateKey(File file) throws IOException, GeneralSecurityException;

    
    /**
     * Reads PKCS#8 formated private key from a buffer, which are each bounded at the beginning by
     * <code>-----BEGIN ... PRIVATE KEY-----</code>, and bounded at the end by <code>-----END ... PRIVATE KEY-----</code>.
     *
     * @param content the private key to encode
     * @return the private key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    PrivateKey getPrivateKey(byte[] content) throws IOException, GeneralSecurityException;

    
    /**
     * Reads PKCS#8 formated private key from a buffer, which are each bounded at the beginning by
     * <code>-----BEGIN ... PRIVATE KEY-----</code>, and bounded at the end by <code>-----END ... PRIVATE KEY-----</code>.
     *
     * @param content the private key to encode
     * @return the private key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    PrivateKey getPrivateKey(String content) throws IOException, GeneralSecurityException;

    
    /**
     * Formats a public key into a well formated X509 certificate (PEM format), which are each bounded at the beginning by
     * <code>-----BEGIN ... PUBLIC KEY-----</code>, and bounded at the end by <code>-----END ... PUBLIC KEY-----</code>.
     *
     * @param publicKey the public key to format
     * @return the well formed certificate
     */
    String formatPublicKey(PublicKey publicKey);

    
    /**
     * Formats a private key to a well formed private key, which is bounded at the beginning by
     * <code>-----BEGIN ... PRIVATE KEY-----</code>, and bounded at the end by <code>-----END ... PRIVATE KEY-----</code>.
     *
     * @param privateKey the private key to format
     * @return the well formed certificate
     */
    String formatPrivateKey(PrivateKey privateKey);

    
    /**
     * Formats a raw base64 encoded PKCS8 to a well formed private key, which is bounded at the beginning by
     * <code>-----BEGIN ... PRIVATE KEY-----</code>, and bounded at the end by <code>-----END ... PRIVATE KEY-----</code>.
     *
     * @param content the raw data to format
     * @return the well formed certificate
     */
    String formatPKCS8(String content);

    
    /**
     * Normalise a raw base64 encoded PKCS8 to a well formed private key.
     *
     * @param content the raw data to normalise
     * @return the normalised private key
     */
    String normalizePKCS8(String content);
}
