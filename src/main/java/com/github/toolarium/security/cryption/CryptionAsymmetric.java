/*
 * CryptionAsymmetric.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.cryption;

import com.github.toolarium.common.ByteArray;
import com.github.toolarium.security.cryption.util.CryptionUtil;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Encrypts and decrypts content of any size with RSA keys (hybrid encryption). For every encryption a new temporary
 * AES key is created and the content is encrypted with it in GCM mode. The temporary key is encrypted with the RSA
 * public key (RSA-OAEP). Only the owner of the private key can decrypt the content; a modified content is detected and
 * rejected.
 *
 * <p>{@link #getInstance()} uses the defaults: the default provider, AES with a 256 bit key, RSA-OAEP with SHA-256 and
 * chunks of 64 KB. Other settings can be chosen with {@link #builder()}; only secure settings are offered. The settings
 * are stored in the encrypted data, so every instance can decrypt the data of any other instance. The keys are passed
 * with every call, so one instance can encrypt for any number of recipients. Large content can be encrypted with
 * {@link #createOutputStream(OutputStream, PublicKey)} and decrypted with
 * {@link #createInputStream(InputStream, PrivateKey)}; the streams and the byte methods use the same format.</p>
 *
 * <p>Format of the encrypted data:</p>
 * <pre>
 * [marker "TCA": 3 bytes] [format version: 1 byte] [chunk size: 4 bytes] [AES key size: 1 byte] [RSA-OAEP hash: 1 byte]
 * [length of the encrypted AES key: 2 bytes] [encrypted AES key] [nonce prefix: 7 bytes]
 * [chunks: encrypted content and authentication tag of every chunk]
 * </pre>
 *
 * <p>The marker "TCA" stands for <b>T</b>oolarium <b>C</b>ryption <b>A</b>symmetric. It identifies data which was
 * encrypted by this class, see {@link #isEncrypted(byte[])}. RSA keys must have at least 2048 bits.</p>
 *
 * @author patrick
 */
public final class CryptionAsymmetric {
    /** The default chunk size: 64 KB */
    public static final int DEFAULT_CHUNK_SIZE = CryptionStreamSupport.DEFAULT_CHUNK_SIZE;

    /** The minimum chunk size: 1 KB */
    public static final int MIN_CHUNK_SIZE = CryptionStreamSupport.MIN_CHUNK_SIZE;

    /** The maximum chunk size: 16 MB */
    public static final int MAX_CHUNK_SIZE = CryptionStreamSupport.MAX_CHUNK_SIZE;

    private static final Logger LOG = LoggerFactory.getLogger(CryptionAsymmetric.class);
    private static final byte[] MARKER = {'T', 'C', 'A'};
    private static final byte FORMAT_VERSION = 1;
    private static final int VERSION_POSITION = MARKER.length;
    private static final int CHUNK_SIZE_POSITION = VERSION_POSITION + 1;
    private static final int AES_KEY_SIZE_POSITION = CHUNK_SIZE_POSITION + 4;
    private static final int OAEP_HASH_POSITION = AES_KEY_SIZE_POSITION + 1;
    private static final int KEY_LENGTH_POSITION = OAEP_HASH_POSITION + 1;
    private static final int FIXED_HEADER_SIZE = KEY_LENGTH_POSITION + 2;
    private static final int MIN_RSA_KEY_SIZE = 2048;
    private static final String RSA = "RSA";
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPPadding";
    private final String provider;
    private final AesKeySize aesKeySize;
    private final OaepHash oaepHash;
    private final int chunkSize;


    /**
     * The size of the temporary AES key.
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
    }


    /**
     * The hash algorithm of RSA-OAEP which encrypts the temporary AES key.
     */
    public enum OaepHash {
        /** SHA-256 (default) */
        SHA_256((byte) 1, "SHA-256", MGF1ParameterSpec.SHA256),

        /** SHA-384 */
        SHA_384((byte) 2, "SHA-384", MGF1ParameterSpec.SHA384),

        /** SHA-512 */
        SHA_512((byte) 3, "SHA-512", MGF1ParameterSpec.SHA512);

        private final byte id;
        private final OAEPParameterSpec parameterSpec;


        /**
         * Constructor for OaepHash
         *
         * @param id the id in the encrypted data
         * @param hashAlgorithm the hash algorithm
         * @param mgf1ParameterSpec the MGF1 parameter
         */
        OaepHash(byte id, String hashAlgorithm, MGF1ParameterSpec mgf1ParameterSpec) {
            this.id = id;
            this.parameterSpec = new OAEPParameterSpec(hashAlgorithm, "MGF1", mgf1ParameterSpec, PSource.PSpecified.DEFAULT);
        }


        /**
         * Get the hash by its id.
         *
         * @param id the id
         * @return the hash or null if the id is unknown
         */
        static OaepHash getById(byte id) {
            for (OaepHash value : values()) {
                if (value.id == id) {
                    return value;
                }
            }

            return null;
        }
    }


    /**
     * Builder for a {@link CryptionAsymmetric} with other settings than the defaults.
     */
    public static final class Builder {
        private String provider;
        private AesKeySize aesKeySize;
        private OaepHash oaepHash;
        private int chunkSize;


        /**
         * Constructor for Builder
         */
        private Builder() {
            provider = null;
            aesKeySize = AesKeySize.AES_256;
            oaepHash = OaepHash.SHA_256;
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
         * Set the size of the temporary AES key (default {@link AesKeySize#AES_256}).
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
         * Set the hash algorithm of RSA-OAEP (default {@link OaepHash#SHA_256}).
         *
         * @param oaepHash the hash algorithm
         * @return the builder
         * @throws IllegalArgumentException if the hash algorithm is null
         */
        public Builder oaepHash(OaepHash oaepHash) {
            if (oaepHash == null) {
                throw new IllegalArgumentException("Invalid OAEP hash!");
            }

            this.oaepHash = oaepHash;
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
         * Create the {@link CryptionAsymmetric}.
         *
         * @return the new instance
         */
        public CryptionAsymmetric build() {
            return new CryptionAsymmetric(provider, aesKeySize, oaepHash, chunkSize);
        }
    }


    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static final class HOLDER {
        /** The singleton instance */
        static final CryptionAsymmetric INSTANCE = new CryptionAsymmetric(null, AesKeySize.AES_256, OaepHash.SHA_256, DEFAULT_CHUNK_SIZE);
    }


    /**
     * Constructor
     *
     * @param provider the provider or null for the default provider
     * @param aesKeySize the AES key size
     * @param oaepHash the RSA-OAEP hash
     * @param chunkSize the chunk size
     */
    private CryptionAsymmetric(String provider, AesKeySize aesKeySize, OaepHash oaepHash, int chunkSize) {
        this.provider = provider;
        this.aesKeySize = aesKeySize;
        this.oaepHash = oaepHash;
        this.chunkSize = chunkSize;
    }


    /**
     * Get the instance with the default settings: the default provider, AES with a 256 bit key, RSA-OAEP with SHA-256
     * and chunks of 64 KB.
     *
     * @return the instance
     */
    public static CryptionAsymmetric getInstance() {
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
     * Get the size of the temporary AES key which is used for the encryption.
     *
     * @return the AES key size
     */
    public AesKeySize getAesKeySize() {
        return aesKeySize;
    }


    /**
     * Get the hash algorithm of RSA-OAEP which is used for the encryption.
     *
     * @return the hash algorithm
     */
    public OaepHash getOaepHash() {
        return oaepHash;
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
     * Encrypt the given text with the public key.
     *
     * @param publicKey the RSA public key
     * @param text the text to encrypt (UTF-8)
     * @return the encrypted data as Base64 string
     * @throws GeneralSecurityException in case of error
     */
    public String encrypt(PublicKey publicKey, String text) throws GeneralSecurityException {
        if (text == null) {
            throw new GeneralSecurityException("Invalid data!");
        }

        return Base64.getEncoder().encodeToString(encrypt(publicKey, text.getBytes(StandardCharsets.UTF_8)));
    }


    /**
     * Encrypt the given data with the public key.
     *
     * @param publicKey the RSA public key
     * @param data the data to encrypt
     * @return the encrypted data
     * @throws GeneralSecurityException in case of error
     */
    public ByteArray encrypt(PublicKey publicKey, ByteArray data) throws GeneralSecurityException {
        if (data == null) {
            throw new GeneralSecurityException("Invalid data!");
        }

        return new ByteArray(encrypt(publicKey, data.toBytes()));
    }


    /**
     * Encrypt the given data with the public key.
     *
     * @param publicKey the RSA public key
     * @param data the data to encrypt
     * @return the encrypted data
     * @throws GeneralSecurityException in case of error
     */
    public byte[] encrypt(PublicKey publicKey, byte[] data) throws GeneralSecurityException {
        return CryptionStreamSupport.encrypt(out -> createOutputStream(out, publicKey), data);
    }


    /**
     * Decrypt the given Base64 encoded data with the private key. The settings are taken from the encrypted data.
     *
     * @param privateKey the RSA private key
     * @param base64Data the encrypted data as Base64 string
     * @return the decrypted text (UTF-8)
     * @throws GeneralSecurityException in case of error, e.g. a wrong key or modified data
     */
    public String decrypt(PrivateKey privateKey, String base64Data) throws GeneralSecurityException {
        byte[] data = CryptionStreamSupport.decodeBase64(base64Data);
        if (data == null) {
            throw new GeneralSecurityException(CryptionStreamSupport.INVALID_DATA);
        }

        return new String(decrypt(privateKey, data), StandardCharsets.UTF_8);
    }


    /**
     * Decrypt the given data with the private key. The settings are taken from the encrypted data.
     *
     * @param privateKey the RSA private key
     * @param data the encrypted data
     * @return the decrypted data
     * @throws GeneralSecurityException in case of error, e.g. a wrong key or modified data
     */
    public ByteArray decrypt(PrivateKey privateKey, ByteArray data) throws GeneralSecurityException {
        if (data == null) {
            throw new GeneralSecurityException(CryptionStreamSupport.INVALID_DATA);
        }

        return new ByteArray(decrypt(privateKey, data.toBytes()));
    }


    /**
     * Decrypt the given data with the private key. The settings are taken from the encrypted data.
     *
     * @param privateKey the RSA private key
     * @param data the encrypted data
     * @return the decrypted data
     * @throws GeneralSecurityException in case of error, e.g. a wrong key or modified data
     */
    public byte[] decrypt(PrivateKey privateKey, byte[] data) throws GeneralSecurityException {
        checkKey(privateKey, "private");
        return CryptionStreamSupport.decrypt(in -> createInputStream(in, privateKey), data);
    }


    /**
     * Create a stream which encrypts the written content with the public key. The stream must be closed.
     *
     * @param out the output stream for the encrypted data
     * @param publicKey the RSA public key
     * @return the encrypting stream
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    public CryptionOutputStream createOutputStream(OutputStream out, PublicKey publicKey) throws GeneralSecurityException, IOException {
        return new CryptionOutputStream(out, this, publicKey);
    }


    /**
     * Create a stream which decrypts the content with the private key. The settings are taken from the encrypted data.
     *
     * @param in the input stream of the encrypted data
     * @param privateKey the RSA private key
     * @return the decrypting stream
     * @throws GeneralSecurityException in case of error, e.g. a wrong key or invalid data
     * @throws IOException in case of an I/O error
     */
    public CryptionInputStream createInputStream(InputStream in, PrivateKey privateKey) throws GeneralSecurityException, IOException {
        return new CryptionInputStream(in, this, privateKey);
    }


    /**
     * Check if the given Base64 string has the format of this class: the marker "TCA" and a supported format version.
     * The content itself is not verified.
     *
     * @param base64Data the data as Base64 string
     * @return true if the data has the format of this class
     */
    public boolean isEncrypted(String base64Data) {
        return isEncrypted(CryptionStreamSupport.decodeBase64(base64Data));
    }


    /**
     * Check if the given data has the format of this class: the marker "TCA" and a supported format version. The
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
     * Check if the given data has the format of this class: the marker "TCA" and a supported format version. The
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
     * Create the context of an encryption: a new temporary AES key, encrypted with the public key, and the header.
     *
     * @param publicKey the RSA public key
     * @return the context
     * @throws GeneralSecurityException in case of error
     */
    CryptionContext createEncryptionContext(PublicKey publicKey) throws GeneralSecurityException {
        int rsaKeyLength = checkKey(publicKey, "public");
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypt with {}, OAEP {}, chunk size {}...", aesKeySize, oaepHash, chunkSize);
        }

        byte[] aesKey = CryptionStreamSupport.randomBytes(aesKeySize.length);
        try {
            Cipher rsaCipher = CryptionUtil.getInstance().getCipher(provider, RSA_ALGORITHM);
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepHash.parameterSpec, CryptionStreamSupport.SECURE_RANDOM);
            byte[] encryptedKey = rsaCipher.doFinal(aesKey);
            if (encryptedKey.length != rsaKeyLength) {
                throw new GeneralSecurityException("Unexpected length of the encrypted key: " + encryptedKey.length);
            }

            byte[] header = ByteBuffer.allocate(FIXED_HEADER_SIZE + encryptedKey.length + CryptionStreamSupport.NONCE_PREFIX_SIZE)
                    .put(MARKER).put(FORMAT_VERSION).putInt(chunkSize).put(aesKeySize.id).put(oaepHash.id).putShort((short) encryptedKey.length)
                    .put(encryptedKey).put(CryptionStreamSupport.randomBytes(CryptionStreamSupport.NONCE_PREFIX_SIZE)).array();
            return new CryptionContext(header, aesKey, chunkSize, provider);
        } catch (GeneralSecurityException | RuntimeException e) {
            Arrays.fill(aesKey, (byte) 0);
            throw e;
        }
    }


    /**
     * Read the header and decrypt the temporary AES key with the private key.
     *
     * @param in the input stream of the encrypted data
     * @param privateKey the RSA private key
     * @return the context
     * @throws GeneralSecurityException in case of error, e.g. a wrong key or invalid data
     * @throws IOException in case of an I/O error
     */
    CryptionContext readDecryptionContext(InputStream in, PrivateKey privateKey) throws GeneralSecurityException, IOException {
        final int rsaKeyLength = checkKey(privateKey, "private");
        byte[] fixedHeader = CryptionStreamSupport.readHeader(in, FIXED_HEADER_SIZE);
        if (!isEncrypted(fixedHeader)) {
            throw new GeneralSecurityException(CryptionStreamSupport.INVALID_DATA);
        }

        ByteBuffer fields = ByteBuffer.wrap(fixedHeader);
        int dataChunkSize = fields.getInt(CHUNK_SIZE_POSITION);
        AesKeySize dataAesKeySize = AesKeySize.getById(fixedHeader[AES_KEY_SIZE_POSITION]);
        OaepHash dataOaepHash = OaepHash.getById(fixedHeader[OAEP_HASH_POSITION]);
        if (!CryptionStreamSupport.isValidChunkSize(dataChunkSize) || dataAesKeySize == null || dataOaepHash == null) {
            throw new GeneralSecurityException("Unsupported settings in the encrypted data!");
        }

        int encryptedKeyLength = fields.getShort(KEY_LENGTH_POSITION) & 0xFFFF;
        if (encryptedKeyLength != rsaKeyLength) {
            throw new GeneralSecurityException("The data was not encrypted with a key of this size!");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Decrypt with {}, OAEP {}, chunk size {}...", dataAesKeySize, dataOaepHash, dataChunkSize);
        }

        byte[] header = CryptionStreamSupport.concat(fixedHeader, CryptionStreamSupport.readHeader(in, encryptedKeyLength + CryptionStreamSupport.NONCE_PREFIX_SIZE));
        Cipher rsaCipher = CryptionUtil.getInstance().getCipher(provider, RSA_ALGORITHM);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey, dataOaepHash.parameterSpec);
        byte[] aesKey = rsaCipher.doFinal(header, FIXED_HEADER_SIZE, encryptedKeyLength);
        if (aesKey.length != dataAesKeySize.length) {
            Arrays.fill(aesKey, (byte) 0);
            throw new GeneralSecurityException(CryptionStreamSupport.INVALID_DATA);
        }

        return new CryptionContext(header, aesKey, dataChunkSize, provider);
    }


    /**
     * Check the key: it must be an RSA key with at least 2048 bits.
     *
     * @param key the key
     * @param keyType the key type for the error message
     * @return the length of the RSA modulus in bytes
     * @throws GeneralSecurityException in case of an invalid key
     */
    private int checkKey(Key key, String keyType) throws GeneralSecurityException {
        if (key == null) {
            throw new GeneralSecurityException("Invalid " + keyType + " key!");
        }

        if (!RSA.equalsIgnoreCase(key.getAlgorithm()) || !(key instanceof RSAKey)) {
            throw new GeneralSecurityException("Only RSA keys are supported, not " + key.getAlgorithm() + "!");
        }

        int keySize = ((RSAKey) key).getModulus().bitLength();
        if (keySize < MIN_RSA_KEY_SIZE) {
            throw new GeneralSecurityException("The RSA key must have at least " + MIN_RSA_KEY_SIZE + " bits, not " + keySize + "!");
        }

        return (keySize + 7) / 8;
    }
}
