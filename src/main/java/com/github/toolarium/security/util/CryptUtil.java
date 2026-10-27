/*
 * CryptUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.util;

import com.github.toolarium.common.security.ISecuredSecretValue;
import com.github.toolarium.security.cryption.util.CryptionUtil;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


/**
 * This is a simple util class for initialisation or checks.
 *
 * @author patrick
 * @deprecated use {@link CryptionUtil}; every method delegates to it.
 */
@Deprecated
public final class CryptUtil {
    /** Represents the AES algorithm as string */
    public static final String ALGORITHM_AES = CryptionUtil.ALGORITHM_AES;


    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static final class HOLDER {
        /** the singleton instance */
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
     * @see CryptionUtil#isStrongEncryptionEnabled()
     */
    public boolean isStrongEncryptionEnabled() {
        return CryptionUtil.getInstance().isStrongEncryptionEnabled();
    }


    /**
     * Get cipher
     *
     * @param algorithm the algorithm
     * @return the cipher object
     * @throws GeneralSecurityException in case of error
     * @see CryptionUtil#getCipher(String)
     */
    public Cipher getCipher(String algorithm) throws GeneralSecurityException {
        return CryptionUtil.getInstance().getCipher(algorithm);
    }


    /**
     * Get cipher
     *
     * @param provider the provider
     * @param algorithm the algorithm
     * @return the cipher object
     * @throws GeneralSecurityException in case of error
     * @see CryptionUtil#getCipher(String, String)
     */
    public Cipher getCipher(String provider, String algorithm) throws GeneralSecurityException {
        return CryptionUtil.getInstance().getCipher(provider, algorithm);
    }


    /**
     * Prepare algorithm message
     *
     * @param provider the provider
     * @param algorithm the algorithm
     * @return the prepared message
     * @see CryptionUtil#getAlgorithmMessage(String, String)
     */
    public String getAlgorithmMessage(String provider, String algorithm) {
        return CryptionUtil.getInstance().getAlgorithmMessage(provider, algorithm);
    }


    /**
     * Prepare algorithm max key length
     *
     * @param algorithm the algorithm
     * @return the prepared message
     * @see CryptionUtil#getMaxAllowedKeyLength(String)
     */
    public int getMaxAllowedKeyLength(String algorithm) {
        return CryptionUtil.getInstance().getMaxAllowedKeyLength(algorithm);
    }


    /**
     * Generates a new random salt (16 bytes) for {@link #createSecretKeySpec(char[], byte[], int)}.
     * The salt is not secret and should be stored alongside the ciphertext.
     *
     * @return a new random salt
     * @see CryptionUtil#generateSalt()
     */
    public byte[] generateSalt() {
        return CryptionUtil.getInstance().generateSalt();
    }


    /**
     * Create a SecretKeySpec from a passphrase using PBKDF2WithHmacSHA256 (AES-256) with a library-fixed internal salt.
     *
     * @param passphrase the passphrase as a char array (will be zeroed after use)
     * @return the SecretKeySpec (AES-256)
     * @throws GeneralSecurityException In case of a security error
     * @see CryptionUtil#createSecretKeySpec(char[])
     */
    public SecretKeySpec createSecretKeySpec(char[] passphrase) throws GeneralSecurityException {
        return CryptionUtil.getInstance().createSecretKeySpec(passphrase);
    }


    /**
     * Create a SecretKeySpec from a passphrase using PBKDF2WithHmacSHA256 (AES-256).
     *
     * @param passphrase the passphrase as a char array (will be zeroed after use)
     * @param salt a caller-supplied salt (random and at least 16 bytes, see {@link #generateSalt()})
     * @param iterations the PBKDF2 iteration count (minimum 100 000 recommended)
     * @return the SecretKeySpec (AES-256)
     * @throws GeneralSecurityException In case of a security error or an invalid salt / iteration count
     * @see CryptionUtil#createSecretKeySpec(char[], byte[], int)
     */
    public SecretKeySpec createSecretKeySpec(char[] passphrase, byte[] salt, int iterations) throws GeneralSecurityException {
        return CryptionUtil.getInstance().createSecretKeySpec(passphrase, salt, iterations);
    }


    /**
     * Create a SecretKeySpec from an {@link ISecuredSecretValue} passphrase using PBKDF2WithHmacSHA256 (AES-256) with a
     * library-fixed internal salt.
     *
     * @param passphrase the passphrase
     * @return the SecretKeySpec (AES-256)
     * @throws GeneralSecurityException In case of a security error
     * @see CryptionUtil#createSecretKeySpec(ISecuredSecretValue)
     */
    public SecretKeySpec createSecretKeySpec(ISecuredSecretValue passphrase) throws GeneralSecurityException {
        return CryptionUtil.getInstance().createSecretKeySpec(passphrase);
    }


    /**
     * Create a SecretKeySpec from an {@link ISecuredSecretValue} passphrase using PBKDF2WithHmacSHA256 (AES-256).
     *
     * @param passphrase the passphrase
     * @param salt a caller-supplied salt (random and at least 16 bytes, see {@link #generateSalt()})
     * @param iterations the PBKDF2 iteration count (minimum 100 000 recommended)
     * @return the SecretKeySpec (AES-256)
     * @throws GeneralSecurityException In case of a security error or an invalid salt / iteration count
     * @see CryptionUtil#createSecretKeySpec(ISecuredSecretValue, byte[], int)
     */
    public SecretKeySpec createSecretKeySpec(ISecuredSecretValue passphrase, byte[] salt, int iterations) throws GeneralSecurityException {
        return CryptionUtil.getInstance().createSecretKeySpec(passphrase, salt, iterations);
    }


    /**
     * Create a SecretKeySpec
     *
     * @param key the initial key
     * @param algorithm the algorithm
     * @return the SecretKeySpec
     * @see CryptionUtil#createSecretKeySpec(byte[], String)
     */
    public SecretKeySpec createSecretKeySpec(byte[] key, String algorithm) {
        return CryptionUtil.getInstance().createSecretKeySpec(key, algorithm);
    }
}
