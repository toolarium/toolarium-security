/*
 * ECKeyConverter.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki.impl;

import com.github.toolarium.security.pki.IKeyConverter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


/**
 * Implements the EC {@link IKeyConverter}.
 * 
 * @author patrick
 */
public class ECKeyConverter extends AbstractKeyConverter {
    /** the public EC key start */
    public static final String PUBLIC_EC_KEY_START = "-----BEGIN EC PUBLIC KEY-----";

    /** the public EC key end */
    public static final String PUBLIC_EC_KEY_END = "-----END EC PUBLIC KEY-----";

    /** the private ECA key certificate start */
    public static final String PRIVATE_EC_KEY_START = "-----BEGIN EC PRIVATE KEY-----";

    /** the private EC key certificate end */
    public static final String PRIVATE_EC_KEY_END = "-----END EC PRIVATE KEY-----";

    
    /**
     * Constructor for ECConverter
     */
    public ECKeyConverter() {
        this(null);
    }
    
    
    /**
     * Constructor for ECConverter
     *
     * @param provider the provider or null to use default provider
     */
    public ECKeyConverter(String provider) {
        super(provider, "EC", 256);
    }
    
    
    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#getPublicKey(byte[])
     */
    @Override
    public PublicKey getPublicKey(byte[] content) throws IOException, GeneralSecurityException {
        if (content == null || content.length == 0) {
            return null;
        }
        
        X509EncodedKeySpec spec;
        try {
            spec = new X509EncodedKeySpec(decodePublicKeyPem(content, PUBLIC_EC_KEY_START, PUBLIC_EC_KEY_END));
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("Invalid " + getType() + " public key: " + e.getMessage(), e);
        }

        KeyFactory kf = getKeyFactory();
        return kf.generatePublic(spec);
    }


    /**
     * @see com.github.toolarium.security.pki.IPKIConverter#getPrivateKey(com.github.toolarium.common.ByteArray)
    @Override
    public PrivateKey getPrivateKey(ByteArray buffer) throws GeneralSecurityException {
        if (buffer == null || buffer.length() == 0) {
            return null;
        }
        
        ByteArray normalizedData = normalizePKCS8(buffer);

        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(normalizedData.toBytes()));
        if (LOG.isDebugEnabled()) {
            LOG.debug("File format of EC private key is: {}", privKeySpec.getFormat());
        }
        PrivateKey privateKey = KeyFactory.getInstance(getType()).generatePrivate(privKeySpec);
        if (LOG.isDebugEnabled()) {
            LOG.debug("File format of EC private key is: {}", privateKey.getFormat());
        }
        return privateKey;
    }
     */


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#formatPublicKey(java.security.PublicKey)
     */
    @Override
    public String formatPublicKey(PublicKey publicKey) {
        if (publicKey == null) {
            return null;
        }
        
        return formatPublicKeyPem(publicKey, PUBLIC_EC_KEY_START, PUBLIC_EC_KEY_END);
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#formatPKCS8(java.lang.String)
     */
    @Override
    public String formatPKCS8(String content) {
        return formatPrivateKeyPem(content, PRIVATE_EC_KEY_START, PRIVATE_EC_KEY_END);
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#normalizePKCS8(java.lang.String)
     */
    @Override
    public String normalizePKCS8(String content) {
        return normalizePrivateKeyPem(content, PRIVATE_EC_KEY_START, PRIVATE_EC_KEY_END);
    }
}
