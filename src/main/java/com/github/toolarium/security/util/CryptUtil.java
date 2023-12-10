/*
 * CryptUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.util;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This is a simple util class for initialisation or checks.
 * 
 * @author patrick
 */
public final class CryptUtil {
    /** Represents the AES algorithm as string */
    public static final String ALGORITHM_AES = "AES";
    
    private static final Logger LOG = LoggerFactory.getLogger(CryptUtil.class);
    private static Boolean isStrongEncryptionIsEnabled = null; 
    private static final String STRONG_CRYPTION_HELP = 
            "=================================================================\n"
            + "To have access to strong cryption you have to download the \n"
            + "\"Unlimited Strength Jurisdiction Policy Files\" from the oracle \n"
            + "download page where you can download the J2SE. Install the jar \n"
            + "files in the lib/security directory of yout J2SE installation.\n"
            + "=================================================================";
    

    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final CryptUtil INSTANCE = new CryptUtil();
    }

    
    /**
     * Constructor
     */
    private CryptUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static CryptUtil getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Check if strong cryption is enabled or not 
     * 
     * @return true if strong cryption is enabled; otherwise false
     */
    public synchronized boolean isStrongEncryptionEnabled() {
        if (isStrongEncryptionIsEnabled == null) {
            // try to get access to strong encryption part
            try {
                final KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_AES);
                keyGen.init(256);
                final SecretKey key = keyGen.generateKey();

                final Cipher testCipher = getCipher(ALGORITHM_AES);
                testCipher.init(Cipher.ENCRYPT_MODE, key);
                isStrongEncryptionIsEnabled = Boolean.TRUE;
            } catch (Exception e) {
                isStrongEncryptionIsEnabled = Boolean.FALSE;
            }

            if (LOG.isDebugEnabled()) {
                if (isStrongEncryptionIsEnabled.booleanValue()) {
                    LOG.debug("Strong cryption is enabled.");
                } else {
                    LOG.debug("Strong cryption is disabled." + "\n" + STRONG_CRYPTION_HELP);
                }
            }
        }
        
        return isStrongEncryptionIsEnabled.booleanValue();
    }

    
    /**
     * Get cipher
     * 
     * @param algorithm the algorithm
     * @return the cipher object
     * @throws GeneralSecurityException in case of error
     */
    public Cipher getCipher(String algorithm) throws GeneralSecurityException {
        return getCipher(null, algorithm);
    }

    
    /**
     * Get cipher
     * 
     * @param provider the provider
     * @param algorithm the algorithm
     * @return the cipher object
     * @throws GeneralSecurityException in case of error
     */
    public Cipher getCipher(String provider, String algorithm) throws GeneralSecurityException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Get cipher object (" + getAlgorithmMessage(provider, algorithm) + ")...");
        }
        
        // Get a cipher object for encryption.
        Cipher cipher = null;
        if (provider != null && provider.length() > 0) {
            cipher = Cipher.getInstance(algorithm, provider);
        } else {
            cipher = Cipher.getInstance(algorithm);
        }
        
        return cipher;
    }
    

    /**
     * Prepare algorithm message 
     * 
     * @param provider the provider
     * @param algorithm the algorithm
     * @return the prepared message
     */
    public String getAlgorithmMessage(String provider, String algorithm) {
        String algo = algorithm;
        if (provider != null && provider.trim().length() > 0) {
            algo = provider.trim() + "/" + algo;
        }
        return algo;
    }

    
    /**
     * Prepare algorithm max key length 
     * 
     * @param algorithm the algorithm
     * @return the prepared message
     */
    public int getMaxAllowedKeyLength(String algorithm) {
        try {
            return Cipher.getMaxAllowedKeyLength(algorithm);
        } catch (NoSuchAlgorithmException e) {
            // NOP
        }

        return -1;
    }

    
    /**
     * Create a SecretKeySpec 
     * 
     * @param keyString the key as string
     * @return the SecretKeySpec
     * @throws UnsupportedEncodingException In case of unsupported encoding
     * @throws NoSuchAlgorithmException In case of invalid algorithm
     */
    public SecretKeySpec createSecretKeySpec(String keyString) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        // hash keyString with SHA-256 and crop the output to 128-bit for key
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(keyString.getBytes("UTF-8"));
        byte[] key = new byte[16];
        System.arraycopy(digest.digest(), 0, key, 0, key.length);
        return createSecretKeySpec(key, "AES");        
    }


    /**
     * Create a SecretKeySpec 
     * 
     * @param key the initial key
     * @param algorithm the algorithm
     * @return the SecretKeySpec
     */
    public SecretKeySpec createSecretKeySpec(byte[] key, String algorithm) {
        String algo = algorithm;
        if (algo != null) {
            int idx = algo.indexOf('/');
            if (idx > 0) {
                algo = algo.substring(0, idx);
            }
            algo = algo.trim();
        }

        return new SecretKeySpec(key, algo);
    }
}
