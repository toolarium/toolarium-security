/*
 * CryptoHashUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.hash;

import com.github.toolarium.security.util.CryptUtil;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
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
    private static class HOLDER {
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
     */
    public byte[] md5(byte[] in) throws GeneralSecurityException {
        return createHash("MD5", in);
    }    
    
    
    /**
     * Creates an SHA1 message digest for the given input.
     * 
     * @param in the input
     * @return the SHA1 message digest for the input
     * @throws GeneralSecurityException in case of error
     */
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
     * @throws UnsupportedEncodingException in case of error
     */
    public byte[] createHashWithKey(String provider, byte[] inputKey, byte[] in)  throws GeneralSecurityException {
        if (in == null) {
            throw new GeneralSecurityException("Invalid input data!");
        }
        
        if (inputKey == null) {
            throw new GeneralSecurityException("Invalid key!");
        }
        
        String algorithm = "SHA-256";
        if (LOG.isInfoEnabled()) {
            LOG.info("Create " + algorithm + " hash (" + in.length + " bytes)...");
        }
        
        // start by getting an object to generate SHA-256 hashes with.
        MessageDigest messageDigestSHA256 = null;

        if (provider == null) {
            messageDigestSHA256 = MessageDigest.getInstance(algorithm);
        } else {
            messageDigestSHA256 = MessageDigest.getInstance(algorithm, provider);
        }
        
        // get the bytes of the keyStr
        byte[] key = inputKey;

        // hash the key if necessary to make it fit in a block (see RFC 2104).
        if (key.length > 64) {
            messageDigestSHA256.update(key);
            key = messageDigestSHA256.digest();
            messageDigestSHA256.reset();
        }

        // pad the key bytes to a block (see RFC 2104).
        byte[] block = new byte[64];
        for (int i = 0; i < key.length; ++i) {
            block[i] = key[i];
        }

        for (int i = key.length; i < block.length; ++i) {
            block[i] = 0;
        }

        // calculate the inner hash, defined in RFC 2104 as SHA-256(KEY ^ IPAD + MESSAGE)), where IPAD is 64 bytes of 0x36.
        for (int i = 0; i < 64; ++i) {
            block[i] ^= 0x36;
        }

        messageDigestSHA256.update(block);
        messageDigestSHA256.update(in);
        final byte[] hash1 = messageDigestSHA256.digest();
        messageDigestSHA256.reset();

        // calculate the outer hash, defined in RFC 2104 as SHA-256(KEY ^ OPAD + INNER_HASH), where OPAD is 64 bytes of 0x5c.
        for (int i = 0; i < 64; ++i) {
            block[i] ^= (0x36 ^ 0x5c);
        }
        messageDigestSHA256.update(block);
        messageDigestSHA256.update(hash1);
        byte[] hash = messageDigestSHA256.digest();

        // return a hexadecimal string representation of the message signature. the outer hash is the message signature, convert its bytes to hexadecimals.
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
