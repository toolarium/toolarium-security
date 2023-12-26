/*
 * KeyConverterFactory.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki;

import com.github.toolarium.security.certificate.impl.CertificateConverter;
import com.github.toolarium.security.pki.impl.DSAKeyConverter;
import com.github.toolarium.security.pki.impl.ECKeyConverter;
import com.github.toolarium.security.pki.impl.RSAKeyConverter;
import java.security.PrivateKey;
import java.security.PublicKey;


/**
 * The key converter factory
 * 
 * @author patrick
 */
public final class KeyConverterFactory {

    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final KeyConverterFactory INSTANCE = new KeyConverterFactory();
    }

    
    /**
     * Constructor
     */
    private KeyConverterFactory() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static KeyConverterFactory getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Get the converter
     *
     * @param privateKey the private key
     * @return the converter
     */
    public IKeyConverter getConverter(PrivateKey privateKey) {
        if (privateKey == null) {
            return null;
        }

        return getConverter(privateKey.getAlgorithm());
    }


    /**
     * Get the converter
     *
     * @param publicKey the public key
     * @return the converter
     */
    public IKeyConverter getConverter(PublicKey publicKey) {
        if (publicKey == null) {
            return null;
        }
        
        return getConverter(publicKey.getAlgorithm());
    }
    

    /**
     * Get the certificate converter
     *
     * @return the certificate converter
     */
    public CertificateConverter getConverter() {
        return new CertificateConverter();
    }

    
    /**
     * Get the converter byased on type / algorithm
     *
     * @param type the type
     * @return the converter
     */
    public IKeyConverter getConverter(Types type) {
        return getConverter(type.name());
    }

    
    /**
     * Get the converter byased on type / algorithm
     *
     * @param type the type
     * @return the converter
     */
    public IKeyConverter getConverter(String type) {
        if ("DSA".equals(type)) {
            return new DSAKeyConverter();
        } else if ("EC".equals(type)) {
            return new ECKeyConverter();
        } else if ("RSA".equals(type)) {
            return new RSAKeyConverter();
        }
        
        return new RSAKeyConverter();
    }
    
    
    public enum Types {
        RSA,
        DSA,
        EC;
    }
}
