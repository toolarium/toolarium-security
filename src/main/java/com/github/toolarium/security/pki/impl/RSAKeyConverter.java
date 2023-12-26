/*
 * AbstractKeyConverter.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki.impl;


import com.github.toolarium.common.ByteArray;
import com.github.toolarium.security.pki.IKeyConverter;
import com.github.toolarium.security.pki.impl.rsa.RSAPrivateKeyPKCS8;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Implements the RSA {@link IKeyConverter}.
 * 
 * @author patrick
 */
public class RSAKeyConverter extends AbstractKeyConverter {

    /** the public RSA key start */
    public static final String PUBLIC_RSA_KEY_START = "-----BEGIN RSA PUBLIC KEY-----";

    /** the public RSA key end */
    public static final String PUBLIC_RSA_KEY_END = "-----END RSA PUBLIC KEY-----";

    /** the public DSA key end */
    public static final String PUBLIC_DSA_KEY_END = "-----END DSA PUBLIC KEY-----";

    /** the private RSA key certificate start */
    public static final String PRIVATE_RSA_KEY_START = "-----BEGIN RSA PRIVATE KEY-----";

    /** the private RSA key certificate end */
    public static final String PRIVATE_RSA_KEY_END = "-----END RSA PRIVATE KEY-----";

    private static final Logger LOG = LoggerFactory.getLogger(RSAKeyConverter.class);

    
    /**
     * Constructor for RSAConverter
     */
    public RSAKeyConverter() {
        this(null);
    }
    
    
    /**
     * Constructor for RSAConverter
     *
     * @param provider the provider or null to use default provider
     */
    public RSAKeyConverter(String provider) {
        super(provider, "RSA", 2048);
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
        ByteArray t = new ByteArray(content).replace(new ByteArray(PUBLIC_RSA_KEY_START), new ByteArray());
        t = t.replace(new ByteArray(PUBLIC_RSA_KEY_END), new ByteArray());
        t = t.replace(new ByteArray("\r"), new ByteArray());
        t = t.replace(new ByteArray(NL), new ByteArray());

        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(t.toBytes()));
        KeyFactory kf = KeyFactory.getInstance(getType());
        return kf.generatePublic(spec);
    }


    /**
     * @see com.github.toolarium.security.pki.impl.AbstractKeyConverter#getPrivateKey(java.lang.String)
     */
    @Override
    public PrivateKey getPrivateKey(String content) throws GeneralSecurityException {
        if (content == null || content.length() == 0) {
            return null;
        }
        
        String normalizedData = normalizePKCS8(content);

        PrivateKey privateKey = null;
        try {
            return super.getPrivateKey(normalizedData);
        } catch (InvalidKeySpecException e) {
            RSAPrivateKeyPKCS8 privKeySpec = new RSAPrivateKeyPKCS8(Base64.getDecoder().decode(normalizedData.getBytes()));
            privKeySpec.checkEncoding();
            privateKey = privKeySpec;
            if (LOG.isDebugEnabled()) {
                LOG.debug("File format of " + getType() + " private key is: " + privateKey.getFormat());
            }
        }
        
        return privateKey;
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#formatPublicKey(java.security.PublicKey)
     */
    @Override
    public String formatPublicKey(PublicKey publicKey) {
        return PKIUtil.getInstance().formatBuffer(new ByteArray(Base64.getEncoder().encode(publicKey.getEncoded())), 64, PUBLIC_RSA_KEY_START, PUBLIC_RSA_KEY_END).toString();
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#formatPKCS8(java.lang.String)
     */
    @Override
    public String formatPKCS8(String content) {
        return PKIUtil.getInstance().formatBuffer(content, 64, PRIVATE_RSA_KEY_START, PRIVATE_RSA_KEY_END);
    }
    

    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#normalizePKCS8(java.lang.String)
     */
    @Override
    public String normalizePKCS8(String content) {
        return PKIUtil.getInstance().normalizeBuffer(content, PRIVATE_RSA_KEY_START, PRIVATE_RSA_KEY_END);
    }
}
