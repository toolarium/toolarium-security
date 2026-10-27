/*
 * CryptionSymmetric.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.cryption;

import com.github.toolarium.common.ByteArray;
import com.github.toolarium.common.security.ISecuredSecretValue;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Encrypts and decrypts content of any size with AES in GCM mode. The key is either an AES key ({@link SecretKey}) or
 * a passphrase. A key is derived from a passphrase with PBKDF2 (HMAC-SHA256) and a new random salt for every
 * encryption. With an AES key a new content key is derived for every encryption (HMAC-SHA256 with a new random salt),
 * so the key can be used for any number of encryptions. A modified content is detected and rejected.
 *
 * <p>{@link #getInstance()} uses the defaults: the default provider, AES with a 256 bit key for passphrases,
 * {@link #DEFAULT_ITERATIONS} PBKDF2 iterations and chunks of 64 KB. Other settings can be chosen with
 * {@link #builder()}. The settings are stored in the encrypted data, so every instance can decrypt the data of any
 * other instance, as long as the PBKDF2 iterations of the data do not exceed its maximum (see
 * {@link Builder#maxIterations(int)}). Large content can be encrypted with the <code>createOutputStream</code> methods and decrypted with
 * the <code>createInputStream</code> methods; the streams and the byte methods use the same format.</p>
 *
 * <p>Format of the encrypted data:</p>
 * <pre>
 * [marker "TCS": 3 bytes] [format version: 1 byte] [chunk size: 4 bytes] [key source: 1 byte, 1 = AES key, 2 = passphrase]
 * only for a passphrase: [AES key size: 1 byte] [PBKDF2 iterations: 4 bytes]
 * [salt: 16 bytes] [nonce prefix: 7 bytes] [chunks: encrypted content and authentication tag of every chunk]
 * </pre>
 *
 * <p>The marker "TCS" stands for <b>T</b>oolarium <b>C</b>ryption <b>S</b>ymmetric. It identifies data which was
 * encrypted by this class, see {@link #isEncrypted(byte[])}. The passphrase arrays of the caller are not changed.</p>
 *
 * @author patrick
 */
public final class CryptionSymmetric {
    /** The default number of PBKDF2 iterations */
    public static final int DEFAULT_ITERATIONS = 100_000;

    /** The maximum number of PBKDF2 iterations which is accepted in encrypted data */
    public static final int MAX_ITERATIONS = 10_000_000;

    /** The default chunk size: 64 KB */
    public static final int DEFAULT_CHUNK_SIZE = CryptionStreamSupport.DEFAULT_CHUNK_SIZE;

    /** The minimum chunk size: 1 KB */
    public static final int MIN_CHUNK_SIZE = CryptionStreamSupport.MIN_CHUNK_SIZE;

    /** The maximum chunk size: 16 MB */
    public static final int MAX_CHUNK_SIZE = CryptionStreamSupport.MAX_CHUNK_SIZE;

    private static final Logger LOG = LoggerFactory.getLogger(CryptionSymmetric.class);
    private static final byte[] MARKER = {'T', 'C', 'S'};
    private static final byte FORMAT_VERSION = 1;
    private static final byte SOURCE_KEY = 1;
    private static final byte SOURCE_PASSPHRASE = 2;
    private static final int VERSION_POSITION = MARKER.length;
    private static final int CHUNK_SIZE_POSITION = VERSION_POSITION + 1;
    private static final int SOURCE_POSITION = CHUNK_SIZE_POSITION + 4;
    private static final int FIXED_HEADER_SIZE = SOURCE_POSITION + 1;
    private static final int PASSPHRASE_SETTINGS_SIZE = 1 + 4;
    private static final int SALT_SIZE = 16;
    private static final String AES = "AES";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String INVALID_PASSPHRASE = "Invalid passphrase!";
    private static final String UNSUPPORTED_SETTINGS = "Unsupported settings in the encrypted data!";
    private static final int DEFAULT_MAX_ITERATIONS = 2 * DEFAULT_ITERATIONS;
    private final String provider;
    private final AesKeySize aesKeySize;
    private final int iterations;
    private final int maxIterations;
    private final int chunkSize;


    /**
     * The size of the AES key.
     */
    public enum AesKeySize {
        /** AES with a 128 bit key */
        AES_128((byte) 1, 16),

        /** AES with a 192 bit key */
        AES_192((byte) 2, 24),

        /** AES with a 256 bit key (default) */
        AES_256((byte) 3, 32);

        private final byte id;
        private final int length;


        /**
         * Constructor for AesKeySize
         *
         * @param id the id in the encrypted data
         * @param length the key length in bytes
         */
        AesKeySize(byte id, int length) {
            this.id = id;
            this.length = length;
        }


        /**
         * Get the key size by its id.
         *
         * @param id the id
         * @return the key size or null if the id is unknown
         */
        static AesKeySize getById(byte id) {
            for (AesKeySize value : values()) {
                if (value.id == id) {
                    return value;
                }
            }

            return null;
        }


        /**
         * Get the key size by its length in bytes.
         *
         * @param length the length in bytes
         * @return the key size or null if the length is no AES key length
         */
        static AesKeySize getByLength(int length) {
            for (AesKeySize value : values()) {
                if (value.length == length) {
                    return value;
                }
            }

            return null;
        }
    }


    /**
     * Builder for a {@link CryptionSymmetric} with other settings than the defaults.
     */
    public static final class Builder {
        private String provider;
        private AesKeySize aesKeySize;
        private int iterations;
        private int maxIterations;
        private int chunkSize;


        /**
         * Constructor for Builder
         */
        private Builder() {
            provider = null;
            aesKeySize = AesKeySize.AES_256;
            iterations = DEFAULT_ITERATIONS;
            maxIterations = 0;
            chunkSize = DEFAULT_CHUNK_SIZE;
        }


        /**
         * Set the security provider for the ciphers (default null: the default provider of the JVM).
         *
         * @param provider the provider name, e.g. "BC", or null for the default provider
         * @return the builder
         */
        public Builder provider(String provider) {
            this.provider = provider;
            return this;
        }


        /**
         * Set the size of the AES key which is derived from a passphrase or created by {@link #generateKey()} (default
         * {@link AesKeySize#AES_256}). With an AES key the size of the given key is used.
         *
         * @param aesKeySize the AES key size
         * @return the builder
         * @throws IllegalArgumentException if the AES key size is null
         */
        public Builder aesKeySize(AesKeySize aesKeySize) {
            if (aesKeySize == null) {
                throw new IllegalArgumentException("Invalid AES key size!");
            }

            this.aesKeySize = aesKeySize;
            return this;
        }


        /**
         * Set the number of PBKDF2 iterations to derive a key from a passphrase (default {@link #DEFAULT_ITERATIONS}).
         *
         * @param iterations the number of iterations, between 1 and {@link #MAX_ITERATIONS}
         * @return the builder
         * @throws IllegalArgumentException if the number of iterations is out of range
         */
        public Builder iterations(int iterations) {
            if (iterations < 1 || iterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException("Invalid number of iterations: " + iterations);
            }

            this.iterations = iterations;
            return this;
        }


        /**
         * Set the maximum number of PBKDF2 iterations which is accepted in encrypted data when it is decrypted with a
         * passphrase. Data with more iterations is rejected before the key is derived, so manipulated data can not
         * force an expensive key derivation. Default: twice {@link #DEFAULT_ITERATIONS}, but at least the configured
         * {@link #iterations(int)}.
         *
         * @param maxIterations the maximum number of iterations, between 1 and {@link #MAX_ITERATIONS}
         * @return the builder
         * @throws IllegalArgumentException if the number of iterations is out of range
         */
        public Builder maxIterations(int maxIterations) {
            if (maxIterations < 1 || maxIterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException("Invalid maximum number of iterations: " + maxIterations);
            }

            this.maxIterations = maxIterations;
            return this;
        }


        /**
         * Set the chunk size: the content is encrypted in chunks of this size (default {@link #DEFAULT_CHUNK_SIZE}).
         * Decryption needs memory for one chunk.
         *
         * @param chunkSize the chunk size in bytes, between {@link #MIN_CHUNK_SIZE} and {@link #MAX_CHUNK_SIZE}
         * @return the builder
         * @throws IllegalArgumentException if the chunk size is out of range
         */
        public Builder chunkSize(int chunkSize) {
            if (!CryptionStreamSupport.isValidChunkSize(chunkSize)) {
                throw new IllegalArgumentException("Invalid chunk size: " + chunkSize);
            }

            this.chunkSize = chunkSize;
            return this;
        }


        /**
         * Create the {@link CryptionSymmetric}.
         *
         * @return the new instance
         * @throws IllegalArgumentException if the maximum number of iterations is less than the number of iterations
         */
        public CryptionSymmetric build() {
            int max = maxIterations;
            if (max == 0) {
                max = Math.max(DEFAULT_MAX_ITERATIONS, iterations);
            } else if (max < iterations) {
                throw new IllegalArgumentException("The maximum number of iterations " + max + " is less than the number of iterations " + iterations + "!");
            }

            return new CryptionSymmetric(provider, aesKeySize, iterations, max, chunkSize);
        }
    }


    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static final class HOLDER {
        /** The singleton instance */
        static final CryptionSymmetric INSTANCE = new CryptionSymmetric(null, AesKeySize.AES_256, DEFAULT_ITERATIONS, DEFAULT_MAX_ITERATIONS, DEFAULT_CHUNK_SIZE);
    }


    /**
     * Constructor
     *
     * @param provider the provider or null for the default provider
     * @param aesKeySize the AES key size
     * @param iterations the number of PBKDF2 iterations
     * @param maxIterations the maximum number of PBKDF2 iterations which is accepted in encrypted data
     * @param chunkSize the chunk size
     */
    private CryptionSymmetric(String provider, AesKeySize aesKeySize, int iterations, int maxIterations, int chunkSize) {
        this.provider = provider;
        this.aesKeySize = aesKeySize;
        this.iterations = iterations;
        this.maxIterations = maxIterations;
        this.chunkSize = chunkSize;
    }


    /**
     * Get the instance with the default settings: the default provider, AES with a 256 bit key,
     * {@link #DEFAULT_ITERATIONS} PBKDF2 iterations and chunks of 64 KB.
     *
     * @return the instance
     */
    public static CryptionSymmetric getInstance() {
        return HOLDER.INSTANCE;
    }


    /**
     * Create a builder to choose other settings than the defaults.
     *
     * @return the builder
     */
    public static Builder builder() {
        return new Builder();
    }


    /**
     * Get the security provider for the ciphers.
     *
     * @return the provider name or null for the default provider
     */
    public String getProvider() {
        return provider;
    }


    /**
     * Get the size of the AES key which is derived from a passphrase or created by {@link #generateKey()}.
     *
     * @return the AES key size
     */
    public AesKeySize getAesKeySize() {
        return aesKeySize;
    }


    /**
     * Get the number of PBKDF2 iterations to derive a key from a passphrase.
     *
     * @return the number of iterations
     */
    public int getIterations() {
        return iterations;
    }


    /**
     * Get the chunk size which is used for the encryption.
     *
     * @return the chunk size in bytes
     */
    public int getChunkSize() {
        return chunkSize;
    }


    /**
     * Create a new random AES key with the configured key size.
     *
     * @return the new AES key
     */
    public SecretKey generateKey() {
        byte[] key = CryptionStreamSupport.randomBytes(aesKeySize.length);
        try {
            return new SecretKeySpec(key, AES);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }


    /**
     * Encrypt the given text with the AES key.
     *
     * @param key the AES key
     * @param text the text to encrypt (UTF-8)
     * @return the encrypted data as Base64 string
     * @throws GeneralSecurityException in case of error
     */
    public String encrypt(SecretKey key, String text) throws GeneralSecurityException {
        return Base64.getEncoder().encodeToString(encrypt(key, toBytes(text)));
    }


    /**
     * Encrypt the given data with the AES key.
     *
     * @param key the AES key
     * @param data the data to encrypt
     * @return the encrypted data
     * @throws GeneralSecurityException in case of error
     */
    public ByteArray encrypt(SecretKey key, ByteArray data) throws GeneralSecurityException {
        return new ByteArray(encrypt(key, toBytes(data)));
    }


    /**
     * Encrypt the given data with the AES key.
     *
     * @param key the AES key
     * @param data the data to encrypt
     * @return the encrypted data
     * @throws GeneralSecurityException in case of error
     */
    public byte[] encrypt(SecretKey key, byte[] data) throws GeneralSecurityException {
        return CryptionStreamSupport.encrypt(out -> createOutputStream(out, key), data);
    }


    /**
     * Encrypt the given text with a key derived from the passphrase.
     *
     * @param passphrase the passphrase, it is not changed
     * @param text the text to encrypt (UTF-8)
     * @return the encrypted data as Base64 string
     * @throws GeneralSecurityException in case of error
     */
    public String encrypt(char[] passphrase, String text) throws GeneralSecurityException {
        return Base64.getEncoder().encodeToString(encrypt(passphrase, toBytes(text)));
    }


    /**
     * Encrypt the given data with a key derived from the passphrase.
     *
     * @param passphrase the passphrase, it is not changed
     * @param data the data to encrypt
     * @return the encrypted data
     * @throws GeneralSecurityException in case of error
     */
    public ByteArray encrypt(char[] passphrase, ByteArray data) throws GeneralSecurityException {
        return new ByteArray(encrypt(passphrase, toBytes(data)));
    }


    /**
     * Encrypt the given data with a key derived from the passphrase.
     *
     * @param passphrase the passphrase, it is not changed
     * @param data the data to encrypt
     * @return the encrypted data
     * @throws GeneralSecurityException in case of error
     */
    public byte[] encrypt(char[] passphrase, byte[] data) throws GeneralSecurityException {
        return CryptionStreamSupport.encrypt(out -> createOutputStream(out, passphrase), data);
    }


    /**
     * Encrypt the given text with a key derived from the passphrase.
     *
     * @param passphrase the passphrase
     * @param text the text to encrypt (UTF-8)
     * @return the encrypted data as Base64 string
     * @throws GeneralSecurityException in case of error
     */
    public String encrypt(ISecuredSecretValue passphrase, String text) throws GeneralSecurityException {
        return Base64.getEncoder().encodeToString(encrypt(passphrase, toBytes(text)));
    }


    /**
     * Encrypt the given data with a key derived from the passphrase.
     *
     * @param passphrase the passphrase
     * @param data the data to encrypt
     * @return the encrypted data
     * @throws GeneralSecurityException in case of error
     */
    public ByteArray encrypt(ISecuredSecretValue passphrase, ByteArray data) throws GeneralSecurityException {
        return new ByteArray(encrypt(passphrase, toBytes(data)));
    }


    /**
     * Encrypt the given data with a key derived from the passphrase.
     *
     * @param passphrase the passphrase
     * @param data the data to encrypt
     * @return the encrypted data
     * @throws GeneralSecurityException in case of error
     */
    public byte[] encrypt(ISecuredSecretValue passphrase, byte[] data) throws GeneralSecurityException {
        return CryptionStreamSupport.encrypt(out -> createOutputStream(out, passphrase), data);
    }


    /**
     * Decrypt the given Base64 encoded data with the AES key.
     *
     * @param key the AES key
     * @param base64Data the encrypted data as Base64 string
     * @return the decrypted text (UTF-8)
     * @throws GeneralSecurityException in case of error, e.g. a wrong key or modified data
     */
    public String decrypt(SecretKey key, String base64Data) throws GeneralSecurityException {
        return new String(decrypt(key, toEncryptedBytes(base64Data)), StandardCharsets.UTF_8);
    }


    /**
     * Decrypt the given data with the AES key.
     *
     * @param key the AES key
     * @param data the encrypted data
     * @return the decrypted data
     * @throws GeneralSecurityException in case of error, e.g. a wrong key or modified data
     */
    public ByteArray decrypt(SecretKey key, ByteArray data) throws GeneralSecurityException {
        return new ByteArray(decrypt(key, toEncryptedBytes(data)));
    }


    /**
     * Decrypt the given data with the AES key.
     *
     * @param key the AES key
     * @param data the encrypted data
     * @return the decrypted data
     * @throws GeneralSecurityException in case of error, e.g. a wrong key or modified data
     */
    public byte[] decrypt(SecretKey key, byte[] data) throws GeneralSecurityException {
        return CryptionStreamSupport.decrypt(in -> createInputStream(in, key), data);
    }


    /**
     * Decrypt the given Base64 encoded data with a key derived from the passphrase. The settings are taken from the
     * encrypted data.
     *
     * @param passphrase the passphrase, it is not changed
     * @param base64Data the encrypted data as Base64 string
     * @return the decrypted text (UTF-8)
     * @throws GeneralSecurityException in case of error, e.g. a wrong passphrase or modified data
     */
    public String decrypt(char[] passphrase, String base64Data) throws GeneralSecurityException {
        return new String(decrypt(passphrase, toEncryptedBytes(base64Data)), StandardCharsets.UTF_8);
    }


    /**
     * Decrypt the given data with a key derived from the passphrase. The settings are taken from the encrypted data.
     *
     * @param passphrase the passphrase, it is not changed
     * @param data the encrypted data
     * @return the decrypted data
     * @throws GeneralSecurityException in case of error, e.g. a wrong passphrase or modified data
     */
    public ByteArray decrypt(char[] passphrase, ByteArray data) throws GeneralSecurityException {
        return new ByteArray(decrypt(passphrase, toEncryptedBytes(data)));
    }


    /**
     * Decrypt the given data with a key derived from the passphrase. The settings are taken from the encrypted data.
     *
     * @param passphrase the passphrase, it is not changed
     * @param data the encrypted data
     * @return the decrypted data
     * @throws GeneralSecurityException in case of error, e.g. a wrong passphrase or modified data
     */
    public byte[] decrypt(char[] passphrase, byte[] data) throws GeneralSecurityException {
        return CryptionStreamSupport.decrypt(in -> createInputStream(in, passphrase), data);
    }


    /**
     * Decrypt the given Base64 encoded data with a key derived from the passphrase. The settings are taken from the
     * encrypted data.
     *
     * @param passphrase the passphrase
     * @param base64Data the encrypted data as Base64 string
     * @return the decrypted text (UTF-8)
     * @throws GeneralSecurityException in case of error, e.g. a wrong passphrase or modified data
     */
    public String decrypt(ISecuredSecretValue passphrase, String base64Data) throws GeneralSecurityException {
        return new String(decrypt(passphrase, toEncryptedBytes(base64Data)), StandardCharsets.UTF_8);
    }


    /**
     * Decrypt the given data with a key derived from the passphrase. The settings are taken from the encrypted data.
     *
     * @param passphrase the passphrase
     * @param data the encrypted data
     * @return the decrypted data
     * @throws GeneralSecurityException in case of error, e.g. a wrong passphrase or modified data
     */
    public ByteArray decrypt(ISecuredSecretValue passphrase, ByteArray data) throws GeneralSecurityException {
        return new ByteArray(decrypt(passphrase, toEncryptedBytes(data)));
    }


    /**
     * Decrypt the given data with a key derived from the passphrase. The settings are taken from the encrypted data.
     *
     * @param passphrase the passphrase
     * @param data the encrypted data
     * @return the decrypted data
     * @throws GeneralSecurityException in case of error, e.g. a wrong passphrase or modified data
     */
    public byte[] decrypt(ISecuredSecretValue passphrase, byte[] data) throws GeneralSecurityException {
        return CryptionStreamSupport.decrypt(in -> createInputStream(in, passphrase), data);
    }


    /**
     * Create a stream which encrypts the written content with the AES key. The stream must be closed.
     *
     * @param out the output stream for the encrypted data
     * @param key the AES key
     * @return the encrypting stream
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    public CryptionOutputStream createOutputStream(OutputStream out, SecretKey key) throws GeneralSecurityException, IOException {
        return new CryptionOutputStream(out, this, key);
    }


    /**
     * Create a stream which encrypts the written content with a key derived from the passphrase. The stream must be
     * closed.
     *
     * @param out the output stream for the encrypted data
     * @param passphrase the passphrase, it is not changed
     * @return the encrypting stream
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    public CryptionOutputStream createOutputStream(OutputStream out, char[] passphrase) throws GeneralSecurityException, IOException {
        return new CryptionOutputStream(out, this, passphrase);
    }


    /**
     * Create a stream which encrypts the written content with a key derived from the passphrase. The stream must be
     * closed.
     *
     * @param out the output stream for the encrypted data
     * @param passphrase the passphrase
     * @return the encrypting stream
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    public CryptionOutputStream createOutputStream(OutputStream out, ISecuredSecretValue passphrase) throws GeneralSecurityException, IOException {
        return new CryptionOutputStream(out, this, passphrase);
    }


    /**
     * Create a stream which decrypts the content with the AES key.
     *
     * @param in the input stream of the encrypted data
     * @param key the AES key
     * @return the decrypting stream
     * @throws GeneralSecurityException in case of error, e.g. a wrong key or invalid data
     * @throws IOException in case of an I/O error
     */
    public CryptionInputStream createInputStream(InputStream in, SecretKey key) throws GeneralSecurityException, IOException {
        return new CryptionInputStream(in, this, key);
    }


    /**
     * Create a stream which decrypts the content with a key derived from the passphrase. The settings are taken from
     * the encrypted data.
     *
     * @param in the input stream of the encrypted data
     * @param passphrase the passphrase, it is not changed
     * @return the decrypting stream
     * @throws GeneralSecurityException in case of error, e.g. a wrong passphrase or invalid data
     * @throws IOException in case of an I/O error
     */
    public CryptionInputStream createInputStream(InputStream in, char[] passphrase) throws GeneralSecurityException, IOException {
        return new CryptionInputStream(in, this, passphrase);
    }


    /**
     * Create a stream which decrypts the content with a key derived from the passphrase. The settings are taken from
     * the encrypted data.
     *
     * @param in the input stream of the encrypted data
     * @param passphrase the passphrase
     * @return the decrypting stream
     * @throws GeneralSecurityException in case of error, e.g. a wrong passphrase or invalid data
     * @throws IOException in case of an I/O error
     */
    public CryptionInputStream createInputStream(InputStream in, ISecuredSecretValue passphrase) throws GeneralSecurityException, IOException {
        return new CryptionInputStream(in, this, passphrase);
    }


    /**
     * Check if the given Base64 string has the format of this class: the marker "TCS" and a supported format version.
     * The content itself is not verified.
     *
     * @param base64Data the data as Base64 string
     * @return true if the data has the format of this class
     */
    public boolean isEncrypted(String base64Data) {
        return isEncrypted(CryptionStreamSupport.decodeBase64(base64Data));
    }


    /**
     * Check if the given data has the format of this class: the marker "TCS" and a supported format version. The
     * content itself is not verified.
     *
     * @param data the data
     * @return true if the data has the format of this class
     */
    public boolean isEncrypted(ByteArray data) {
        if (data == null) {
            return false;
        }

        return isEncrypted(data.toBytes());
    }


    /**
     * Check if the given data has the format of this class: the marker "TCS" and a supported format version. The
     * content itself is not verified.
     *
     * @param data the data
     * @return true if the data has the format of this class
     */
    public boolean isEncrypted(byte[] data) {
        if (data == null || data.length < FIXED_HEADER_SIZE) {
            return false;
        }

        for (int i = 0; i < MARKER.length; i++) {
            if (data[i] != MARKER[i]) {
                return false;
            }
        }

        return data[VERSION_POSITION] == FORMAT_VERSION;
    }


    /**
     * Create the context of an encryption with an AES key: a new content key is derived from the key and a new salt.
     *
     * @param key the AES key
     * @return the context
     * @throws GeneralSecurityException in case of error
     */
    CryptionContext createEncryptionContext(SecretKey key) throws GeneralSecurityException {
        byte[] keyBytes = getKeyBytes(key);
        try {
            byte[] salt = CryptionStreamSupport.randomBytes(SALT_SIZE);
            byte[] header = createFixedHeader(SOURCE_KEY, SALT_SIZE + CryptionStreamSupport.NONCE_PREFIX_SIZE)
                    .put(salt).put(CryptionStreamSupport.randomBytes(CryptionStreamSupport.NONCE_PREFIX_SIZE)).array();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Encrypt with AES {} bit key, chunk size {}...", keyBytes.length * 8, chunkSize);
            }

            return new CryptionContext(header, deriveContentKey(keyBytes, salt), chunkSize, provider);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }


    /**
     * Create the context of an encryption with a passphrase: the key is derived from the passphrase and a new salt.
     *
     * @param passphrase the passphrase, it is not changed
     * @return the context
     * @throws GeneralSecurityException in case of error
     */
    CryptionContext createEncryptionContext(char[] passphrase) throws GeneralSecurityException {
        if (passphrase == null) {
            throw new GeneralSecurityException(INVALID_PASSPHRASE);
        }

        byte[] salt = CryptionStreamSupport.randomBytes(SALT_SIZE);
        byte[] header = createFixedHeader(SOURCE_PASSPHRASE, PASSPHRASE_SETTINGS_SIZE + SALT_SIZE + CryptionStreamSupport.NONCE_PREFIX_SIZE)
                .put(aesKeySize.id).putInt(iterations).put(salt).put(CryptionStreamSupport.randomBytes(CryptionStreamSupport.NONCE_PREFIX_SIZE)).array();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypt with passphrase, {}, {} iterations, chunk size {}...", aesKeySize, iterations, chunkSize);
        }

        return new CryptionContext(header, derivePassphraseKey(passphrase, salt, iterations, aesKeySize), chunkSize, provider);
    }


    /**
     * Create the context of an encryption with a passphrase: the key is derived from the passphrase and a new salt.
     *
     * @param passphrase the passphrase
     * @return the context
     * @throws GeneralSecurityException in case of error
     */
    CryptionContext createEncryptionContext(ISecuredSecretValue passphrase) throws GeneralSecurityException {
        return withPassphrase(passphrase, this::createEncryptionContext);
    }


    /**
     * Read the header and derive the content key from the AES key.
     *
     * @param in the input stream of the encrypted data
     * @param key the AES key
     * @return the context
     * @throws GeneralSecurityException in case of error, e.g. invalid data
     * @throws IOException in case of an I/O error
     */
    CryptionContext readDecryptionContext(InputStream in, SecretKey key) throws GeneralSecurityException, IOException {
        byte[] keyBytes = getKeyBytes(key);
        try {
            byte[] fixedHeader = readFixedHeader(in, SOURCE_KEY);
            byte[] header = CryptionStreamSupport.concat(fixedHeader, CryptionStreamSupport.readHeader(in, SALT_SIZE + CryptionStreamSupport.NONCE_PREFIX_SIZE));
            byte[] salt = Arrays.copyOfRange(header, FIXED_HEADER_SIZE, FIXED_HEADER_SIZE + SALT_SIZE);
            return new CryptionContext(header, deriveContentKey(keyBytes, salt), readChunkSize(fixedHeader), provider);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }


    /**
     * Read the header and derive the key from the passphrase.
     *
     * @param in the input stream of the encrypted data
     * @param passphrase the passphrase, it is not changed
     * @return the context
     * @throws GeneralSecurityException in case of error, e.g. invalid data
     * @throws IOException in case of an I/O error
     */
    CryptionContext readDecryptionContext(InputStream in, char[] passphrase) throws GeneralSecurityException, IOException {
        if (passphrase == null) {
            throw new GeneralSecurityException(INVALID_PASSPHRASE);
        }

        byte[] fixedHeader = readFixedHeader(in, SOURCE_PASSPHRASE);
        byte[] header = CryptionStreamSupport.concat(fixedHeader,
                CryptionStreamSupport.readHeader(in, PASSPHRASE_SETTINGS_SIZE + SALT_SIZE + CryptionStreamSupport.NONCE_PREFIX_SIZE));
        AesKeySize dataAesKeySize = AesKeySize.getById(header[FIXED_HEADER_SIZE]);
        int dataIterations = ByteBuffer.wrap(header).getInt(FIXED_HEADER_SIZE + 1);
        if (dataAesKeySize == null || dataIterations < 1 || dataIterations > MAX_ITERATIONS) {
            throw new GeneralSecurityException(UNSUPPORTED_SETTINGS);
        }

        if (dataIterations > maxIterations) {
            throw new GeneralSecurityException("The encrypted data needs " + dataIterations + " iterations, more than the accepted maximum of " + maxIterations + "!");
        }

        int saltPosition = FIXED_HEADER_SIZE + PASSPHRASE_SETTINGS_SIZE;
        byte[] salt = Arrays.copyOfRange(header, saltPosition, saltPosition + SALT_SIZE);
        return new CryptionContext(header, derivePassphraseKey(passphrase, salt, dataIterations, dataAesKeySize), readChunkSize(fixedHeader), provider);
    }


    /**
     * Read the header and derive the key from the passphrase.
     *
     * @param in the input stream of the encrypted data
     * @param passphrase the passphrase
     * @return the context
     * @throws GeneralSecurityException in case of error, e.g. invalid data
     * @throws IOException in case of an I/O error
     */
    CryptionContext readDecryptionContext(InputStream in, ISecuredSecretValue passphrase) throws GeneralSecurityException, IOException {
        try {
            return withPassphrase(passphrase, chars -> {
                try {
                    return readDecryptionContext(in, chars);
                } catch (IOException e) {
                    throw new GeneralSecurityException(e.getMessage(), e);
                }
            });
        } catch (GeneralSecurityException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }

            throw e;
        }
    }


    /**
     * Create the fixed part of the header: marker, format version, chunk size and key source.
     *
     * @param source the key source
     * @param additionalSize the size of the rest of the header
     * @return the buffer of the header, the fixed part is written
     */
    private ByteBuffer createFixedHeader(byte source, int additionalSize) {
        return ByteBuffer.allocate(FIXED_HEADER_SIZE + additionalSize).put(MARKER).put(FORMAT_VERSION).putInt(chunkSize).put(source);
    }


    /**
     * Read and check the fixed part of the header.
     *
     * @param in the input stream
     * @param expectedSource the expected key source
     * @return the fixed part of the header
     * @throws GeneralSecurityException in case of invalid data or an other key source
     * @throws IOException in case of an I/O error
     */
    private byte[] readFixedHeader(InputStream in, byte expectedSource) throws GeneralSecurityException, IOException {
        byte[] fixedHeader = CryptionStreamSupport.readHeader(in, FIXED_HEADER_SIZE);
        if (!isEncrypted(fixedHeader)) {
            throw new GeneralSecurityException(CryptionStreamSupport.INVALID_DATA);
        }

        if (!CryptionStreamSupport.isValidChunkSize(readChunkSize(fixedHeader))) {
            throw new GeneralSecurityException(UNSUPPORTED_SETTINGS);
        }

        byte source = fixedHeader[SOURCE_POSITION];
        if (source != expectedSource) {
            if (source == SOURCE_PASSPHRASE) {
                throw new GeneralSecurityException("The data was encrypted with a passphrase, not with an AES key!");
            } else if (source == SOURCE_KEY) {
                throw new GeneralSecurityException("The data was encrypted with an AES key, not with a passphrase!");
            } else {
                throw new GeneralSecurityException(CryptionStreamSupport.INVALID_DATA);
            }
        }

        return fixedHeader;
    }


    /**
     * Get the chunk size of the header.
     *
     * @param fixedHeader the fixed part of the header
     * @return the chunk size
     */
    private int readChunkSize(byte[] fixedHeader) {
        return ByteBuffer.wrap(fixedHeader).getInt(CHUNK_SIZE_POSITION);
    }


    /**
     * Get the bytes of an AES key.
     *
     * @param key the key
     * @return the key bytes (a copy)
     * @throws GeneralSecurityException in case of an invalid key
     */
    private byte[] getKeyBytes(SecretKey key) throws GeneralSecurityException {
        if (key == null || !AES.equalsIgnoreCase(key.getAlgorithm())) {
            throw new GeneralSecurityException("Invalid AES key!");
        }

        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null || AesKeySize.getByLength(keyBytes.length) == null) {
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }

            throw new GeneralSecurityException("Invalid AES key: it must have 128, 192 or 256 bits!");
        }

        return keyBytes;
    }


    /**
     * Derive the content key from an AES key and a salt (HMAC-SHA256), it has the size of the AES key.
     *
     * @param keyBytes the AES key
     * @param salt the salt
     * @return the content key
     * @throws GeneralSecurityException in case of error
     */
    private byte[] deriveContentKey(byte[] keyBytes, byte[] salt) throws GeneralSecurityException {
        Mac mac;
        if (provider != null && provider.length() > 0) {
            mac = Mac.getInstance(HMAC_ALGORITHM, provider);
        } else {
            mac = Mac.getInstance(HMAC_ALGORITHM);
        }

        mac.init(new SecretKeySpec(keyBytes, HMAC_ALGORITHM));
        mac.update(MARKER);
        byte[] result = mac.doFinal(salt);
        try {
            return Arrays.copyOf(result, keyBytes.length);
        } finally {
            Arrays.fill(result, (byte) 0);
        }
    }


    /**
     * Derive an AES key from the passphrase with PBKDF2.
     *
     * @param passphrase the passphrase, it is not changed
     * @param salt the salt
     * @param iterationCount the number of iterations
     * @param keySize the key size
     * @return the key bytes
     * @throws GeneralSecurityException in case of error
     */
    private byte[] derivePassphraseKey(char[] passphrase, byte[] salt, int iterationCount, AesKeySize keySize) throws GeneralSecurityException {
        PBEKeySpec keySpec = new PBEKeySpec(passphrase, salt, iterationCount, keySize.length * 8);
        try {
            SecretKeyFactory factory;
            if (provider != null && provider.length() > 0) {
                factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM, provider);
            } else {
                factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            }

            return factory.generateSecret(keySpec).getEncoded();
        } finally {
            keySpec.clearPassword();
        }
    }


    /**
     * Run the given function with the characters of the passphrase.
     *
     * @param passphrase the passphrase
     * @param function the function
     * @return the result of the function
     * @throws GeneralSecurityException in case of error
     */
    private CryptionContext withPassphrase(ISecuredSecretValue passphrase, PassphraseFunction function) throws GeneralSecurityException {
        if (passphrase == null || passphrase.getValue() == null) {
            throw new GeneralSecurityException(INVALID_PASSPHRASE);
        }

        try {
            return passphrase.getValue().useChars(chars -> {
                try {
                    return function.apply(chars);
                } catch (GeneralSecurityException e) {
                    throw new IllegalStateException(e);
                }
            });
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof GeneralSecurityException) {
                throw (GeneralSecurityException) e.getCause();
            }

            throw e;
        }
    }


    /**
     * Get the bytes of the data to encrypt.
     *
     * @param data the data
     * @return the bytes
     * @throws GeneralSecurityException if the data is null
     */
    private byte[] toBytes(ByteArray data) throws GeneralSecurityException {
        if (data == null) {
            throw new GeneralSecurityException("Invalid data!");
        }

        return data.toBytes();
    }


    /**
     * Get the bytes of the text to encrypt.
     *
     * @param text the text
     * @return the bytes (UTF-8)
     * @throws GeneralSecurityException if the text is null
     */
    private byte[] toBytes(String text) throws GeneralSecurityException {
        if (text == null) {
            throw new GeneralSecurityException("Invalid data!");
        }

        return text.getBytes(StandardCharsets.UTF_8);
    }


    /**
     * Get the bytes of the encrypted data.
     *
     * @param data the encrypted data
     * @return the bytes
     * @throws GeneralSecurityException if the data is null
     */
    private byte[] toEncryptedBytes(ByteArray data) throws GeneralSecurityException {
        if (data == null) {
            throw new GeneralSecurityException(CryptionStreamSupport.INVALID_DATA);
        }

        return data.toBytes();
    }


    /**
     * Get the bytes of the Base64 encoded data.
     *
     * @param base64Data the encrypted data as Base64 string
     * @return the bytes
     * @throws GeneralSecurityException if the data is no valid Base64 string
     */
    private byte[] toEncryptedBytes(String base64Data) throws GeneralSecurityException {
        byte[] data = CryptionStreamSupport.decodeBase64(base64Data);
        if (data == null) {
            throw new GeneralSecurityException(CryptionStreamSupport.INVALID_DATA);
        }

        return data;
    }


    /**
     * Function which uses the characters of a passphrase.
     */
    @FunctionalInterface
    private interface PassphraseFunction {
        /**
         * Apply the function.
         *
         * @param passphrase the passphrase
         * @return the context
         * @throws GeneralSecurityException in case of error
         */
        CryptionContext apply(char[] passphrase) throws GeneralSecurityException;
    }
}
