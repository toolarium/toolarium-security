/*
 * DSAKeyConverter.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki.impl;

import com.github.toolarium.common.ByteArray;
import com.github.toolarium.security.pki.IKeyConverter;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


/**
 * Implements the DSA {@link IKeyConverter}.
 *  
 * @author patrick
 */
public class DSAKeyConverter extends AbstractKeyConverter {
    /** the public DSA key start */
    public static final String PUBLIC_DSA_KEY_START = "-----BEGIN DSA PUBLIC KEY-----";

    /** the public DSA key end */
    public static final String PUBLIC_DSA_KEY_END = "-----END DSA PUBLIC KEY-----";

    /** the private DSA key certificate start */
    public static final String PRIVATE_DSA_KEY_START = "-----BEGIN DSA PRIVATE KEY-----";

    /** the private DSA key certificate end */
    public static final String PRIVATE_DSA_KEY_END = "-----END DSA PRIVATE KEY-----";

    
    /**
     * Constructor for DSAConverter
     */
    public DSAKeyConverter() {
        this(null);
    }
    
    
    /**
     * Constructor for DSAConverter
     *
     * @param provider the provider or null to use default provider
     */
    public DSAKeyConverter(String provider) {
        super(provider, "DSA", 2048);
    }

    
    /**
     * @see com.github.toolarium.security.pki.impl.AbstractKeyConverter#getPublicKey(byte[])
     */
    @Override
    public PublicKey getPublicKey(byte[] content) throws IOException, GeneralSecurityException {
        if (content == null || content.length == 0) {
            return null;
        }
        
        @SuppressWarnings("resource")
        ByteArray t = new ByteArray(content).replace(new ByteArray(PUBLIC_DSA_KEY_START), new ByteArray());
        t = t.replace(new ByteArray(PUBLIC_DSA_KEY_END), new ByteArray());
        t = t.replace(new ByteArray("\r"), new ByteArray());
        t = t.replace(new ByteArray(NL), new ByteArray());

        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(t.toBytes()));
        KeyFactory kf = KeyFactory.getInstance(getType());
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
        LOG.debug("File format of private key is: " + privKeySpec.getFormat());
        KeyFactory keyFactory = KeyFactory.getInstance(getType());
        return keyFactory.generatePrivate(privKeySpec);
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
        
        return PKIUtil.getInstance().formatBuffer(new ByteArray(Base64.getEncoder().encode(publicKey.getEncoded())), 64, PUBLIC_DSA_KEY_START, PUBLIC_DSA_KEY_END).toString();
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#formatPKCS8(java.lang.String)
     */
    @Override
    public String formatPKCS8(String content) {
        return PKIUtil.getInstance().formatBuffer(content, 64, PRIVATE_DSA_KEY_START, PRIVATE_DSA_KEY_END);
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#normalizePKCS8(java.lang.String)
     */
    @Override
    public String normalizePKCS8(String content) {
        return PKIUtil.getInstance().normalizeBuffer(content, PRIVATE_DSA_KEY_START, PRIVATE_DSA_KEY_END);
    }
}
