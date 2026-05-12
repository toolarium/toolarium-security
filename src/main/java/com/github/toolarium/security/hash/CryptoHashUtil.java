/*
 * CryptoHashUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.hash;

import com.github.toolarium.security.util.CryptUtil;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This util class provides a fassade to the cryptographic hash functions of the java API.
 * 
 * @author patrick
 */
public final class CryptoHashUtil {
    private static final Logger LOG = LoggerFactory.getLogger(CryptoHashUtil.class);

    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static final class HOLDER {
        static final CryptoHashUtil INSTANCE = new CryptoHashUtil();
    }

    
    /**
     * Constructor
     */
    private CryptoHashUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static CryptoHashUtil getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Creates an MD5 message digest for the given input.
     *
     * @param in the input
     * @return the md5 message digest for the input
     * @throws GeneralSecurityException in case of error
     * @deprecated MD5 is cryptographically broken. Use {@link #sha256(byte[])} or {@link #sha512(byte[])} instead.
     */
    @Deprecated
    public byte[] md5(byte[] in) throws GeneralSecurityException {
        return createHash("MD5", in);
    }


    /**
     * Creates an SHA1 message digest for the given input.
     *
     * @param in the input
     * @return the SHA1 message digest for the input
     * @throws GeneralSecurityException in case of error
     * @deprecated SHA-1 is cryptographically weak. Use {@link #sha256(byte[])} or {@link #sha512(byte[])} instead.
     */
    @Deprecated
    public byte[] sha1(byte[] in) throws GeneralSecurityException {
        return createHash("SHA1", in);
    }
    
    
    /**
     * Creates an SHA-256 message digest for the given input. 
     * This should be your best choice to verify signatures and certificates.
     * 
     * @param in the input
     * @return the SHA-256 message digest for the input
     * @throws GeneralSecurityException in case of error
     */
    public byte[] sha256(byte[] in) throws GeneralSecurityException {
        return createHash("SHA-256", in);
    }

    
    /**
     * Creates an SHA-512 message digest for the given input.
     * 
     * @param in the input
     * @return the SHA-256 message digest for the input
     * @throws GeneralSecurityException in case of error
     */
    public byte[] sha512(byte[] in) throws GeneralSecurityException {
        return createHash("SHA-512", in);
    }


    /**
     * Creates an message digest of the given algorithm for the given input.
     * 
     * @param algorithm the name of the digest algorithm to use
     * @param in the input
     * @return the message digest for the input
     * @throws GeneralSecurityException in case of error
     */
    public byte[] createHash(String algorithm, byte[] in) throws GeneralSecurityException {
        return createHash(null, algorithm, in);
    }
    
    
    /**
     * Creates an message digest of the given algorithm for the given input
     * 
     * @param provider the provider to use
     * @param algorithm the name of the digest algorithm to use
     * @param in the input
     * @return the message digest for the input
     * @throws GeneralSecurityException in case of error
     */
    public byte[] createHash(String provider, String algorithm, byte[] in) throws GeneralSecurityException {
        if (algorithm == null) {
            throw new GeneralSecurityException("Invalid message digest name.");
        }
        
        if (in == null) {
            throw new GeneralSecurityException("Invalid input data!");
        }
        
        if (LOG.isInfoEnabled()) {
            LOG.info("Create " + CryptUtil.getInstance().getAlgorithmMessage(provider, algorithm) + " hash (" + in.length + " bytes)...");
        }

        MessageDigest msgDigest = null;

        if (provider != null && provider.trim().length() > 0) {
            msgDigest = MessageDigest.getInstance(algorithm, provider);
        } else { 
            msgDigest = MessageDigest.getInstance(algorithm);
        }

        msgDigest.update(in);
        return msgDigest.digest();
    }    
    
    
    /**
     * Creates an message digest of the given algorithm for the given input
     * 
     * @param provider the provider to use
     * @param inputKey the key
     * @param in the input message
     * @return the message digest 
     * @throws GeneralSecurityException in case of error
     */
    public byte[] createHashWithKey(String provider, byte[] inputKey, byte[] in)  throws GeneralSecurityException {
        if (in == null) {
            throw new GeneralSecurityException("Invalid input data!");
        }

        if (inputKey == null) {
            throw new GeneralSecurityException("Invalid key!");
        }

        String macAlgorithm = "HmacSHA256";
        if (LOG.isInfoEnabled()) {
            LOG.info("Create " + macAlgorithm + " hash (" + in.length + " bytes)...");
        }

        Mac mac;
        if (provider != null && provider.trim().length() > 0) {
            mac = Mac.getInstance(macAlgorithm, provider);
        } else {
            mac = Mac.getInstance(macAlgorithm);
        }

        SecretKeySpec keySpec = new SecretKeySpec(inputKey, macAlgorithm);
        mac.init(keySpec);
        byte[] hash = mac.doFinal(in);

        // return a hexadecimal string representation of the HMAC
        byte[] hexadecimals = new byte[hash.length * 2];
        for (int i = 0; i < hash.length; ++i) {
            for (int j = 0; j < 2; ++j) {
                int value = (hash[i] >> (4 - 4 * j)) & 0xf;
                char base = '0';
                if (value >= 10) {
                    base = ('a' - 10);
                }

                hexadecimals[i * 2 + j] = (byte) (base + value);
            }
        }

        return hexadecimals;
    }
}
