/*
 * AbstractKeyConverter.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki.impl;

import com.github.toolarium.common.util.FileUtil;
import com.github.toolarium.security.pki.IKeyConverter;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This key converter base class
 * 
 * @author patrick
 */
public abstract class AbstractKeyConverter implements IKeyConverter {
    /** the standard PEM start of a PKCS#8 private key (RFC 7468) */
    public static final String PRIVATE_KEY_START = "-----BEGIN PRIVATE KEY-----";

    /** the standard PEM end of a PKCS#8 private key (RFC 7468) */
    public static final String PRIVATE_KEY_END = "-----END PRIVATE KEY-----";

    /** the standard PEM start of a X.509 public key (RFC 7468) */
    public static final String PUBLIC_KEY_START = "-----BEGIN PUBLIC KEY-----";

    /** the standard PEM end of a X.509 public key (RFC 7468) */
    public static final String PUBLIC_KEY_END = "-----END PUBLIC KEY-----";

    /**
     * System property to write the key type specific PEM headers (e.g. <code>-----BEGIN RSA PRIVATE KEY-----</code>)
     * as version 1.1.8 and older did: <code>-Dtoolarium.security.legacyPemHeaders=true</code>. By default the standard
     * headers (<code>-----BEGIN PRIVATE KEY-----</code>, <code>-----BEGIN PUBLIC KEY-----</code>) are written, which
     * match the content (PKCS#8 / X.509). Both header variants are always accepted when reading.
     */
    public static final String LEGACY_PEM_HEADERS_PROPERTY = "toolarium.security.legacyPemHeaders";

    /** the new line separator */
    protected static final String NL = "\n";

    private static final Logger LOG = LoggerFactory.getLogger(AbstractKeyConverter.class);
    private String provider;
    private String type;
    private int defaultSize;

    
    /**
     * Constructor for AbstractKeyConverter
     *
     * @param provider the provider
     * @param type the type
     * @param defaultSize the default size
     */
    protected AbstractKeyConverter(String provider, String type, int defaultSize) {
        this.provider = provider;
        this.type = type;
        this.defaultSize = defaultSize;
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#getProvider()
     */
    @Override
    public String getProvider() {
        return provider;
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#getType()
     */
    @Override
    public String getType() {
        return type;
    }

    
    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#generateKeyPair()
     */
    @Override
    public KeyPair generateKeyPair() throws GeneralSecurityException {
        return PKIUtil.getInstance().generateKeyPair(getProvider(), getType(), defaultSize);
    }

    
    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#generateKeyPair(java.lang.String, int)
     */
    @Override
    public KeyPair generateKeyPair(String algorithm, int keySize) throws GeneralSecurityException {
        return PKIUtil.getInstance().generateKeyPair(getProvider(), algorithm, keySize);
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#getPublicKey(java.lang.String)
     */
    @Override
    public PublicKey getPublicKey(String content) throws IOException, GeneralSecurityException {
        if (content == null || content.length() == 0) {
            return null;
        }
        
        return getPublicKey(content.getBytes());
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#getPublicKey(java.io.File)
     */
    @Override
    public PublicKey getPublicKey(File file) throws IOException, GeneralSecurityException {
        if (file == null) {
            return null;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Loading " + getType() + " public key form file '" + file + "'...");
        }
        
        return getPublicKey(FileUtil.getInstance().readFileContent(file));
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#getPrivateKey(byte[])
     */
    @Override
    public PrivateKey getPrivateKey(byte[] content) throws IOException, GeneralSecurityException {
        return getPrivateKey(new String(content));
    }
    

    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#getPrivateKey(java.lang.String)
     */
    @Override
    public PrivateKey getPrivateKey(String content) throws GeneralSecurityException {
        if (content == null || content.length() == 0) {
            return null;
        }
        
        String normalizedData = normalizePKCS8(content);
        byte[] decoded = Base64.getDecoder().decode(normalizedData.getBytes());
        PrivateKey privateKey;
        try {
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(decoded);

            if (LOG.isDebugEnabled()) {
                LOG.debug("File format of " + getType() + " private key is: " + privKeySpec.getFormat());
            }

            privateKey = KeyFactory.getInstance(getType()).generatePrivate(privKeySpec);
        } finally {
            // the spec keeps its own copy; clear the decoded key material
            Arrays.fill(decoded, (byte) 0);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("File format of " + getType() + " private key is: " + privateKey.getFormat());
        }
        
        return privateKey;
    }
    
    
    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#getPrivateKey(java.io.File)
     */
    @Override
    public PrivateKey getPrivateKey(File file) throws IOException, GeneralSecurityException {
        if (file == null) {
            return null;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Loading " + getType() + " private key form file '" + file + "'...");
        }
        
        return getPrivateKey(FileUtil.getInstance().readFileContent(file));
    }


    /**
     * @see com.github.toolarium.security.pki.IKeyConverter#formatPrivateKey(java.security.PrivateKey)
     */
    @Override
    public String formatPrivateKey(PrivateKey privateKey) {
        if (privateKey == null) {
            return null;
        }

        byte[] encoded = privateKey.getEncoded();
        try {
            return formatPKCS8(new String(Base64.getEncoder().encode(encoded)));
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }


    /**
     * Check if the key type specific (legacy) PEM headers should be written, see {@link #LEGACY_PEM_HEADERS_PROPERTY}.
     *
     * @return true to write the legacy PEM headers
     */
    protected boolean isLegacyPemHeaders() {
        return Boolean.getBoolean(LEGACY_PEM_HEADERS_PROPERTY);
    }


    /**
     * Format a base64 encoded PKCS#8 private key as PEM, with the standard or the legacy header.
     *
     * @param content the base64 encoded PKCS#8 private key
     * @param legacyStart the key type specific PEM start
     * @param legacyEnd the key type specific PEM end
     * @return the PEM formatted private key
     */
    protected String formatPrivateKeyPem(String content, String legacyStart, String legacyEnd) {
        if (isLegacyPemHeaders()) {
            return PKIUtil.getInstance().formatBuffer(content, 64, legacyStart, legacyEnd);
        }
        return PKIUtil.getInstance().formatBuffer(content, 64, PRIVATE_KEY_START, PRIVATE_KEY_END);
    }


    /**
     * Remove the standard or the legacy PEM header and footer and the line breaks of a private key.
     *
     * @param content the PEM formatted private key
     * @param legacyStart the key type specific PEM start
     * @param legacyEnd the key type specific PEM end
     * @return the base64 encoded private key
     */
    protected String normalizePrivateKeyPem(String content, String legacyStart, String legacyEnd) {
        String data = PKIUtil.getInstance().normalizeBuffer(content, legacyStart, legacyEnd);
        return PKIUtil.getInstance().normalizeBuffer(data, PRIVATE_KEY_START, PRIVATE_KEY_END);
    }


    /**
     * Format a public key (X.509 encoded) as PEM, with the standard or the legacy header.
     *
     * @param publicKey the public key
     * @param legacyStart the key type specific PEM start
     * @param legacyEnd the key type specific PEM end
     * @return the PEM formatted public key
     */
    protected String formatPublicKeyPem(PublicKey publicKey, String legacyStart, String legacyEnd) {
        String content = new String(Base64.getEncoder().encode(publicKey.getEncoded()));
        if (isLegacyPemHeaders()) {
            return PKIUtil.getInstance().formatBuffer(content, 64, legacyStart, legacyEnd);
        }
        return PKIUtil.getInstance().formatBuffer(content, 64, PUBLIC_KEY_START, PUBLIC_KEY_END);
    }


    /**
     * Decode a PEM formatted public key with the standard or the legacy header.
     *
     * @param content the PEM formatted public key
     * @param legacyStart the key type specific PEM start
     * @param legacyEnd the key type specific PEM end
     * @return the X.509 encoded public key
     */
    protected byte[] decodePublicKeyPem(byte[] content, String legacyStart, String legacyEnd) {
        String data = PKIUtil.getInstance().normalizeBuffer(new String(content), legacyStart, legacyEnd);
        data = PKIUtil.getInstance().normalizeBuffer(data, PUBLIC_KEY_START, PUBLIC_KEY_END);
        return Base64.getDecoder().decode(data.trim());
    }
}
