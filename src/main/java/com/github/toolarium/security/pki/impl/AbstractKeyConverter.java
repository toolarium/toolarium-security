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
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This key converter base class
 * 
 * @author patrick
 */
public abstract class AbstractKeyConverter implements IKeyConverter {
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
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(normalizedData.getBytes()));
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("File format of " + getType() + " private key is: " + privKeySpec.getFormat());
        }
        
        PrivateKey privateKey = KeyFactory.getInstance(getType()).generatePrivate(privKeySpec);
        
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
        
        return formatPKCS8(new String(Base64.getEncoder().encode(privateKey.getEncoded())));
    }
}
