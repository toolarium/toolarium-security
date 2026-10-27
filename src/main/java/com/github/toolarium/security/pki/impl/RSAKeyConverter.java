/*
 * AbstractKeyConverter.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki.impl;


import com.github.toolarium.security.pki.IKeyConverter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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
        
        X509EncodedKeySpec spec;
        try {
            spec = new X509EncodedKeySpec(decodePublicKeyPem(content, PUBLIC_RSA_KEY_START, PUBLIC_RSA_KEY_END));
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("Invalid " + getType() + " public key: " + e.getMessage(), e);
        }

        KeyFactory kf = getKeyFactory();
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
        
        String normalizedData;
        try {
            normalizedData = normalizePKCS8(content);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("Invalid " + getType() + " private key: " + e.getMessage(), e);
        }

        try {
            return super.getPrivateKey(normalizedData);
        } catch (InvalidKeySpecException e) {
            // not PKCS#8: try PKCS#1 (e.g. openssl genrsa -traditional), which is wrapped into PKCS#8
            byte[] decoded = null;
            byte[] pkcs8 = null;
            try {
                // invalid base64 is a RuntimeException and is reported as InvalidKeySpecException below
                decoded = Base64.getDecoder().decode(normalizedData.getBytes());
                org.bouncycastle.asn1.pkcs.RSAPrivateKey pkcs1 = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(decoded);
                PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), pkcs1);
                pkcs8 = privateKeyInfo.getEncoded();
                PrivateKey privateKey = getKeyFactory().generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Converted PKCS#1 {} private key into {}.", getType(), privateKey.getFormat());
                }
                return privateKey;
            } catch (IOException | RuntimeException | GeneralSecurityException ex) {
                InvalidKeySpecException result = new InvalidKeySpecException("Invalid " + getType() + " private key (neither PKCS#8 nor PKCS#1): " + e.getMessage(), e);
                result.addSuppressed(ex);
                throw result;
            } finally {
                // clear the decoded key material
                if (decoded != null) {
                    Arrays.fill(decoded, (byte) 0);
                }
                if (pkcs8 != null) {
                    Arrays.fill(pkcs8, (byte) 0);
                }
            }
        }
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#formatPublicKey(java.security.PublicKey)
     */
    @Override
    public String formatPublicKey(PublicKey publicKey) {
        if (publicKey == null) {
            return null;
        }

        return formatPublicKeyPem(publicKey, PUBLIC_RSA_KEY_START, PUBLIC_RSA_KEY_END);
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#formatPKCS8(java.lang.String)
     */
    @Override
    public String formatPKCS8(String content) {
        return formatPrivateKeyPem(content, PRIVATE_RSA_KEY_START, PRIVATE_RSA_KEY_END);
    }
    

    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#normalizePKCS8(java.lang.String)
     */
    @Override
    public String normalizePKCS8(String content) {
        return normalizePrivateKeyPem(content, PRIVATE_RSA_KEY_START, PRIVATE_RSA_KEY_END);
    }
}
