/*
 * CryptUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.util;

import com.github.toolarium.common.security.ISecuredSecretValue;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
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
    private static volatile Boolean isStrongEncryptionIsEnabled = null;
    private static final String STRONG_CRYPTION_HELP =
            "=================================================================\n"
            + "To have access to strong cryption you have to download the \n"
            + "\"Unlimited Strength Jurisdiction Policy Files\" from the oracle \n"
            + "download page where you can download the J2SE. Install the jar \n"
            + "files in the lib/security directory of yout J2SE installation.\n"
            + "=================================================================";
    private static final byte[] PBKDF2_SALT = "toolarium-security-v1".getBytes(StandardCharsets.UTF_8);
    private static final int PBKDF2_ITERATIONS = 100_000;
    private static final int PBKDF2_KEY_LENGTH_BITS = 256;
    private static final int PBKDF2_MIN_SALT_LENGTH = 16;
    private static final SecureRandom SALT_RANDOM = new SecureRandom();


    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static final class HOLDER {
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
    public boolean isStrongEncryptionEnabled() {
        Boolean result = isStrongEncryptionIsEnabled;
        if (result == null) {
            synchronized (CryptUtil.class) {
                result = isStrongEncryptionIsEnabled;
                if (result == null) {
                    // try to get access to strong encryption part
                    try {
                        final KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_AES);
                        keyGen.init(256);
                        final SecretKey key = keyGen.generateKey();

                        final Cipher testCipher = getCipher(ALGORITHM_AES + "/ECB/PKCS5Padding");
                        testCipher.init(Cipher.ENCRYPT_MODE, key);
                        result = Boolean.TRUE;
                    } catch (Exception e) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Strong cryption is disabled." + "\n" + STRONG_CRYPTION_HELP);
                        }
                        return false; // do not cache failure — allow retry
                    }

                    isStrongEncryptionIsEnabled = result;
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Strong cryption is enabled.");
                    }
                }
            }
        }

        return result.booleanValue();
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
        if (algorithm != null && !algorithm.contains("/")) {
            LOG.warn("Cipher algorithm '" + algorithm + "' specified without mode/padding — defaults to ECB which is insecure for block ciphers. Use e.g. 'AES/GCM/NoPadding'.");
        }

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
     * Generates a new random salt (16 bytes) for {@link #createSecretKeySpec(char[], byte[], int)}.
     * The salt is not secret and should be stored alongside the ciphertext.
     *
     * @return a new random salt
     */
    public byte[] generateSalt() {
        byte[] salt = new byte[PBKDF2_MIN_SALT_LENGTH];
        SALT_RANDOM.nextBytes(salt);
        return salt;
    }


    /**
     * Create a SecretKeySpec from a passphrase using PBKDF2WithHmacSHA256 (AES-256).
     *
     * <p><strong>Note:</strong> this overload uses a library-fixed internal salt for
     * backward-compatibility only: the same passphrase produces the same key in every
     * installation, which enables pre-computation attacks. Use
     * {@link #createSecretKeySpec(char[], byte[], int)} with a salt from {@link #generateSalt()}
     * stored alongside the ciphertext.</p>
     *
     * @param passphrase the passphrase as a char array (will be zeroed after use)
     * @return the SecretKeySpec (AES-256)
     * @throws GeneralSecurityException In case of a security error
     */
    public SecretKeySpec createSecretKeySpec(char[] passphrase) throws GeneralSecurityException {
        return createSecretKeySpec(passphrase, PBKDF2_SALT, PBKDF2_ITERATIONS);
    }


    /**
     * Create a SecretKeySpec from a passphrase using PBKDF2WithHmacSHA256 (AES-256).
     *
     * @param passphrase the passphrase as a char array (will be zeroed after use)
     * @param salt a caller-supplied salt (random and at least 16 bytes, see {@link #generateSalt()})
     * @param iterations the PBKDF2 iteration count (minimum 100 000 recommended)
     * @return the SecretKeySpec (AES-256)
     * @throws GeneralSecurityException In case of a security error or an invalid salt / iteration count
     */
    public SecretKeySpec createSecretKeySpec(char[] passphrase, byte[] salt, int iterations) throws GeneralSecurityException {
        try {
            if (passphrase == null) {
                throw new GeneralSecurityException("Passphrase must not be null.");
            }
            if (salt == null || salt.length < PBKDF2_MIN_SALT_LENGTH) {
                throw new GeneralSecurityException("Salt must have at least " + PBKDF2_MIN_SALT_LENGTH + " bytes.");
            }
            if (iterations < 1) {
                throw new GeneralSecurityException("Invalid iteration count: " + iterations);
            }

            PBEKeySpec pbeSpec = new PBEKeySpec(passphrase, salt, iterations, PBKDF2_KEY_LENGTH_BITS);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] key = factory.generateSecret(pbeSpec).getEncoded();
                try {
                    return createSecretKeySpec(key, "AES");
                } finally {
                    java.util.Arrays.fill(key, (byte) 0);
                }
            } finally {
                pbeSpec.clearPassword();
            }
        } finally {
            if (passphrase != null) {
                java.util.Arrays.fill(passphrase, '\0');
            }
        }
    }


    /**
     * Create a SecretKeySpec from an {@link ISecuredSecretValue} passphrase using PBKDF2WithHmacSHA256 (AES-256).
     *
     * <p><strong>Note:</strong> this overload uses a library-fixed internal salt for
     * backward-compatibility only: the same passphrase produces the same key in every
     * installation. Use {@link #createSecretKeySpec(ISecuredSecretValue, byte[], int)} with a
     * salt from {@link #generateSalt()}.</p>
     *
     * @param passphrase the passphrase
     * @return the SecretKeySpec (AES-256)
     * @throws GeneralSecurityException In case of a security error
     */
    public SecretKeySpec createSecretKeySpec(ISecuredSecretValue passphrase) throws GeneralSecurityException {
        return createSecretKeySpec(passphrase, PBKDF2_SALT, PBKDF2_ITERATIONS);
    }


    /**
     * Create a SecretKeySpec from an {@link ISecuredSecretValue} passphrase using PBKDF2WithHmacSHA256 (AES-256).
     *
     * @param passphrase the passphrase
     * @param salt a caller-supplied salt (random and at least 16 bytes, see {@link #generateSalt()})
     * @param iterations the PBKDF2 iteration count (minimum 100 000 recommended)
     * @return the SecretKeySpec (AES-256)
     * @throws GeneralSecurityException In case of a security error or an invalid salt / iteration count
     */
    public SecretKeySpec createSecretKeySpec(ISecuredSecretValue passphrase, byte[] salt, int iterations) throws GeneralSecurityException {
        if (passphrase == null || passphrase.getValue() == null) {
            throw new GeneralSecurityException("Passphrase must not be null.");
        }
        try {
            return passphrase.getValue().useChars(chars -> {
                try {
                    return createSecretKeySpec(chars, salt, iterations);
                } catch (GeneralSecurityException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (RuntimeException e) {
            Throwable cause = e.getCause();
            if (cause instanceof GeneralSecurityException) {
                throw (GeneralSecurityException) cause;
            }
            throw e;
        }
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
