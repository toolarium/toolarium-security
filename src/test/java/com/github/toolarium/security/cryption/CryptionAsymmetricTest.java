/*
 * CryptionAsymmetricTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.cryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.common.ByteArray;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;


/**
 * Test the {@link CryptionAsymmetric}.
 *
 * @author patrick
 */
public class CryptionAsymmetricTest {
    private static final String RSA = "RSA";
    private static final String TEXT = "Hello world, äöü €!";
    private static final String SIZE = "size ";
    private static final int CHUNK_SIZE = 1024;
    private static final int CHUNK_SIZE_POSITION = 4;
    private static final int TAG_SIZE = 16;
    private static final int NONCE_PREFIX_SIZE = 7;
    private static final int[] STREAM_SIZES = {0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, CHUNK_SIZE * 2, CHUNK_SIZE * 5 + 7};
    private static final int AES_KEY_SIZE_POSITION = 8;
    private static final int OAEP_HASH_POSITION = 9;
    private static final int HEADER_SIZE = 12;
    private static KeyPair keyPair;


    /**
     * Constructor for CryptionAsymmetricTest
     */
    public CryptionAsymmetricTest() {
        // NOP
    }


    /**
     * Create the key pair.
     *
     * @throws GeneralSecurityException in case of error
     */
    @BeforeAll
    public static void setUp() throws GeneralSecurityException {
        keyPair = PKIUtil.getInstance().generateKeyPair(null, RSA, 2048);
    }


    /**
     * Encrypt and decrypt bytes, a {@link ByteArray} and a text.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testRoundTrip() throws GeneralSecurityException {
        CryptionAsymmetric cryption = CryptionAsymmetric.getInstance();
        byte[] data = TEXT.getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = cryption.encrypt(keyPair.getPublic(), data);
        assertTrue(cryption.isEncrypted(encrypted));
        assertArrayEquals(data, cryption.decrypt(keyPair.getPrivate(), encrypted));

        ByteArray encryptedByteArray = cryption.encrypt(keyPair.getPublic(), new ByteArray(data));
        assertTrue(cryption.isEncrypted(encryptedByteArray));
        assertArrayEquals(data, cryption.decrypt(keyPair.getPrivate(), encryptedByteArray).toBytes());

        String encryptedText = cryption.encrypt(keyPair.getPublic(), TEXT);
        assertTrue(cryption.isEncrypted(encryptedText));
        assertEquals(TEXT, cryption.decrypt(keyPair.getPrivate(), encryptedText));
    }


    /**
     * Empty and large data (larger than an RSA block) and a 4096 bit key.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testDataSizesAndKeySize() throws GeneralSecurityException {
        CryptionAsymmetric cryption = CryptionAsymmetric.getInstance();
        assertArrayEquals(new byte[0], cryption.decrypt(keyPair.getPrivate(), cryption.encrypt(keyPair.getPublic(), new byte[0])));

        byte[] data = new byte[1024 * 1024];
        new SecureRandom().nextBytes(data);
        assertArrayEquals(data, cryption.decrypt(keyPair.getPrivate(), cryption.encrypt(keyPair.getPublic(), data)));

        KeyPair keyPair4096 = PKIUtil.getInstance().generateKeyPair(null, RSA, 4096);
        assertArrayEquals(data, cryption.decrypt(keyPair4096.getPrivate(), cryption.encrypt(keyPair4096.getPublic(), data)));
    }


    /**
     * Every encryption uses a new temporary key, the result differs for the same data.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testNewTemporaryKeyPerEncryption() throws GeneralSecurityException {
        byte[] data = TEXT.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted1 = CryptionAsymmetric.getInstance().encrypt(keyPair.getPublic(), data);
        byte[] encrypted2 = CryptionAsymmetric.getInstance().encrypt(keyPair.getPublic(), data);
        assertFalse(Arrays.equals(encrypted1, encrypted2));
    }


    /**
     * Streams: the stream and the byte methods use the same format, with the constructors and the factory methods,
     * for empty data, data smaller than a chunk, exactly one and two chunks and more than two chunks.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testStreamRoundTrip() throws Exception {
        CryptionAsymmetric cryption = CryptionAsymmetric.builder().chunkSize(CHUNK_SIZE).build();
        for (int size : STREAM_SIZES) {
            byte[] data = randomData(size);

            ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
            try (CryptionOutputStream out = new CryptionOutputStream(encrypted, cryption, keyPair.getPublic())) {
                out.write(data);
            }
            assertTrue(cryption.isEncrypted(encrypted.toByteArray()));
            assertArrayEquals(data, CryptionAsymmetric.getInstance().decrypt(keyPair.getPrivate(), encrypted.toByteArray()), SIZE + size);
            assertArrayEquals(data, readAll(new CryptionInputStream(new ByteArrayInputStream(encrypted.toByteArray()), cryption, keyPair.getPrivate())), SIZE + size);
            assertArrayEquals(data, readAll(cryption.createInputStream(new ByteArrayInputStream(cryption.encrypt(keyPair.getPublic(), data)), keyPair.getPrivate())), SIZE + size);

            encrypted = new ByteArrayOutputStream();
            try (CryptionOutputStream out = cryption.createOutputStream(encrypted, keyPair.getPublic())) {
                out.write(data);
            }
            assertArrayEquals(data, cryption.decrypt(keyPair.getPrivate(), encrypted.toByteArray()), SIZE + size);
        }
    }


    /**
     * Streams: single bytes can be written and read.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testStreamSingleBytes() throws Exception {
        CryptionAsymmetric cryption = CryptionAsymmetric.builder().chunkSize(CHUNK_SIZE).build();
        byte[] data = randomData(CHUNK_SIZE * 2 + 5);

        ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
        try (CryptionOutputStream out = cryption.createOutputStream(encrypted, keyPair.getPublic())) {
            for (byte b : data) {
                out.write(b);
            }
        }

        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        try (CryptionInputStream in = cryption.createInputStream(new ByteArrayInputStream(encrypted.toByteArray()), keyPair.getPrivate())) {
            int b = in.read();
            while (b >= 0) {
                decrypted.write(b);
                b = in.read();
            }
        }
        assertArrayEquals(data, decrypted.toByteArray());
    }


    /**
     * Streams: removed, swapped or appended chunks are detected; the stream throws an {@link IOException} with the cause.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testStreamModifiedChunks() throws Exception {
        CryptionAsymmetric cryption = CryptionAsymmetric.builder().chunkSize(CHUNK_SIZE).build();
        byte[] encrypted = cryption.encrypt(keyPair.getPublic(), randomData(CHUNK_SIZE * 3));
        int headerSize = HEADER_SIZE + 256 + NONCE_PREFIX_SIZE;
        int encryptedChunkSize = CHUNK_SIZE + TAG_SIZE;
        assertEquals(headerSize + 3 * encryptedChunkSize, encrypted.length);
        assertModifiedChunksRejected(encrypted, headerSize, encryptedChunkSize, data -> cryption.decrypt(keyPair.getPrivate(), data));

        byte[] lastChunkRemoved = Arrays.copyOf(encrypted, encrypted.length - encryptedChunkSize);
        try (InputStream in = cryption.createInputStream(new ByteArrayInputStream(lastChunkRemoved), keyPair.getPrivate())) {
            IOException e = assertThrows(IOException.class, () -> readAll(in));
            assertTrue(e.getCause() instanceof GeneralSecurityException);
        }
    }


    /**
     * Streams: the chunk size is validated in the builder and in the encrypted data; the chunk size of the data is
     * used, not the one of the decrypting instance.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testStreamChunkSize() throws GeneralSecurityException {
        assertEquals(CryptionAsymmetric.DEFAULT_CHUNK_SIZE, CryptionAsymmetric.getInstance().getChunkSize());
        assertEquals(CHUNK_SIZE, CryptionAsymmetric.builder().chunkSize(CHUNK_SIZE).build().getChunkSize());
        assertThrows(IllegalArgumentException.class, () -> CryptionAsymmetric.builder().chunkSize(CryptionAsymmetric.MIN_CHUNK_SIZE - 1));
        assertThrows(IllegalArgumentException.class, () -> CryptionAsymmetric.builder().chunkSize(CryptionAsymmetric.MAX_CHUNK_SIZE + 1));

        byte[] data = randomData(CHUNK_SIZE * 3);
        byte[] encrypted = CryptionAsymmetric.builder().chunkSize(CHUNK_SIZE).build().encrypt(keyPair.getPublic(), data);
        assertEquals(CHUNK_SIZE, ByteBuffer.wrap(encrypted).getInt(CHUNK_SIZE_POSITION));
        assertArrayEquals(data, CryptionAsymmetric.getInstance().decrypt(keyPair.getPrivate(), encrypted));

        ByteBuffer.wrap(encrypted).putInt(CHUNK_SIZE_POSITION, Integer.MAX_VALUE);
        assertThrows(GeneralSecurityException.class, () -> CryptionAsymmetric.getInstance().decrypt(keyPair.getPrivate(), encrypted));
    }


    /**
     * Streams: invalid arguments of the constructors are rejected.
     */
    @Test
    public void testStreamInvalidArguments() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertThrows(GeneralSecurityException.class, () -> new CryptionOutputStream(out, (CryptionAsymmetric) null, keyPair.getPublic()));
        assertThrows(GeneralSecurityException.class, () -> new CryptionOutputStream(out, CryptionAsymmetric.getInstance(), null));
        assertThrows(IOException.class, () -> new CryptionOutputStream(null, CryptionAsymmetric.getInstance(), keyPair.getPublic()));
        assertThrows(IOException.class, () -> new CryptionInputStream(null, CryptionAsymmetric.getInstance(), keyPair.getPrivate()));
        assertThrows(GeneralSecurityException.class, () -> new CryptionInputStream(new ByteArrayInputStream(new byte[] {1, 2, 3}), CryptionAsymmetric.getInstance(), keyPair.getPrivate()));
    }


    /**
     * Streams: the key of the context is destroyed when the stream is closed and can not be used anymore.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testStreamContextDestroyed() throws Exception {
        CryptionContext context = CryptionAsymmetric.getInstance().createEncryptionContext(keyPair.getPublic());
        assertFalse(context.isDestroyed());
        context.destroy();
        assertTrue(context.isDestroyed());
        assertThrows(IllegalStateException.class, () -> context.getKey());

        CryptionOutputStream out = CryptionAsymmetric.getInstance().createOutputStream(new ByteArrayOutputStream(), keyPair.getPublic());
        out.close();
        assertThrows(IOException.class, () -> out.write(1));
    }


    /**
     * The builder: every combination of the settings works, the settings are stored in the encrypted data and every
     * instance can decrypt the data of an other instance.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testBuilder() throws GeneralSecurityException {
        CryptionAsymmetric defaultCryption = CryptionAsymmetric.getInstance();
        assertEquals(CryptionAsymmetric.AesKeySize.AES_256, defaultCryption.getAesKeySize());
        assertEquals(CryptionAsymmetric.OaepHash.SHA_256, defaultCryption.getOaepHash());
        assertEquals(CryptionAsymmetric.AesKeySize.AES_256, CryptionAsymmetric.builder().build().getAesKeySize());

        byte[] data = TEXT.getBytes(StandardCharsets.UTF_8);
        for (CryptionAsymmetric.AesKeySize aesKeySize : CryptionAsymmetric.AesKeySize.values()) {
            for (CryptionAsymmetric.OaepHash oaepHash : CryptionAsymmetric.OaepHash.values()) {
                CryptionAsymmetric cryption = CryptionAsymmetric.builder().aesKeySize(aesKeySize).oaepHash(oaepHash).build();
                assertEquals(aesKeySize, cryption.getAesKeySize());
                assertEquals(oaepHash, cryption.getOaepHash());

                byte[] encrypted = cryption.encrypt(keyPair.getPublic(), data);
                assertEquals(aesKeySize.ordinal() + 1, encrypted[AES_KEY_SIZE_POSITION]);
                assertEquals(oaepHash.ordinal() + 1, encrypted[OAEP_HASH_POSITION]);
                assertArrayEquals(data, cryption.decrypt(keyPair.getPrivate(), encrypted));
                assertArrayEquals(data, defaultCryption.decrypt(keyPair.getPrivate(), encrypted), aesKeySize + " / " + oaepHash);
            }
        }

        assertThrows(IllegalArgumentException.class, () -> CryptionAsymmetric.builder().aesKeySize(null));
        assertThrows(IllegalArgumentException.class, () -> CryptionAsymmetric.builder().oaepHash(null));
    }


    /**
     * The provider of the builder is used: a known provider works, an unknown provider is rejected.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testProvider() throws GeneralSecurityException {
        assertEquals(null, CryptionAsymmetric.getInstance().getProvider());

        CryptionAsymmetric cryption = CryptionAsymmetric.builder().provider("SunJCE").build();
        assertEquals("SunJCE", cryption.getProvider());
        byte[] data = TEXT.getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(data, cryption.decrypt(keyPair.getPrivate(), cryption.encrypt(keyPair.getPublic(), data)));

        CryptionAsymmetric unknownProvider = CryptionAsymmetric.builder().provider("UnknownProvider").build();
        assertThrows(GeneralSecurityException.class, () -> unknownProvider.encrypt(keyPair.getPublic(), data));
    }


    /**
     * Modified data is rejected: the content, the encrypted key and the header.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testModifiedData() throws GeneralSecurityException {
        CryptionAsymmetric cryption = CryptionAsymmetric.getInstance();
        byte[] encrypted = cryption.encrypt(keyPair.getPublic(), TEXT.getBytes(StandardCharsets.UTF_8));

        // last byte (authentication tag), first byte of the encrypted key, length of the encrypted key, AES key size, OAEP hash
        int[] positions = {encrypted.length - 1, HEADER_SIZE, HEADER_SIZE - 1, AES_KEY_SIZE_POSITION, OAEP_HASH_POSITION};
        for (int position : positions) {
            byte[] modified = encrypted.clone();
            modified[position] ^= 1;
            assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(keyPair.getPrivate(), modified), "position " + position);
        }

        // truncated
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(keyPair.getPrivate(), Arrays.copyOf(encrypted, encrypted.length - 1)));
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(keyPair.getPrivate(), Arrays.copyOf(encrypted, HEADER_SIZE + 10)));
    }


    /**
     * The data can not be decrypted with an other private key.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testWrongPrivateKey() throws GeneralSecurityException {
        KeyPair otherKeyPair = PKIUtil.getInstance().generateKeyPair(null, RSA, 2048);
        byte[] encrypted = CryptionAsymmetric.getInstance().encrypt(keyPair.getPublic(), TEXT.getBytes(StandardCharsets.UTF_8));
        assertThrows(GeneralSecurityException.class, () -> CryptionAsymmetric.getInstance().decrypt(otherKeyPair.getPrivate(), encrypted));
    }


    /**
     * Unknown settings in the encrypted data are rejected.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testUnknownSettings() throws GeneralSecurityException {
        byte[] encrypted = CryptionAsymmetric.getInstance().encrypt(keyPair.getPublic(), TEXT.getBytes(StandardCharsets.UTF_8));
        int[] positions = {AES_KEY_SIZE_POSITION, OAEP_HASH_POSITION};
        for (int position : positions) {
            byte[] modified = encrypted.clone();
            modified[position] = 99;
            assertThrows(GeneralSecurityException.class, () -> CryptionAsymmetric.getInstance().decrypt(keyPair.getPrivate(), modified), "position " + position);
        }
    }


    /**
     * Invalid keys and data are rejected: no key, an EC key, an RSA key with less than 2048 bits and no data.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testInvalidInput() throws GeneralSecurityException {
        CryptionAsymmetric cryption = CryptionAsymmetric.getInstance();
        byte[] data = TEXT.getBytes(StandardCharsets.UTF_8);
        KeyPair ecKeyPair = PKIUtil.getInstance().generateKeyPair(null, "EC", 256);
        KeyPair smallKeyPair = PKIUtil.getInstance().generateKeyPair(null, RSA, 1024);

        assertThrows(GeneralSecurityException.class, () -> cryption.encrypt(null, data));
        assertThrows(GeneralSecurityException.class, () -> cryption.encrypt(ecKeyPair.getPublic(), data));
        assertThrows(GeneralSecurityException.class, () -> cryption.encrypt(smallKeyPair.getPublic(), data));
        assertThrows(GeneralSecurityException.class, () -> cryption.encrypt(keyPair.getPublic(), (byte[]) null));
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(null, new byte[] {1}));
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(ecKeyPair.getPrivate(), new byte[] {1}));
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(keyPair.getPrivate(), (byte[]) null));
    }


    /**
     * The marker and the format version are detected.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testIsEncrypted() throws GeneralSecurityException {
        CryptionAsymmetric cryption = CryptionAsymmetric.getInstance();
        byte[] encrypted = cryption.encrypt(keyPair.getPublic(), TEXT.getBytes(StandardCharsets.UTF_8));
        assertEquals('T', encrypted[0]);
        assertEquals('C', encrypted[1]);
        assertEquals('A', encrypted[2]);
        assertEquals(1, encrypted[3]);

        assertFalse(cryption.isEncrypted((byte[]) null));
        assertFalse(cryption.isEncrypted((String) null));
        assertFalse(cryption.isEncrypted(TEXT.getBytes(StandardCharsets.UTF_8)));
        assertFalse(cryption.isEncrypted("no base64!"));

        byte[] otherVersion = encrypted.clone();
        otherVersion[3] = 2;
        assertFalse(cryption.isEncrypted(otherVersion));
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(keyPair.getPrivate(), otherVersion));
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(keyPair.getPrivate(), Base64.getEncoder().encodeToString(TEXT.getBytes(StandardCharsets.UTF_8))));
    }


    /**
     * Check that removed, swapped and appended chunks are rejected.
     *
     * @param encrypted the encrypted data with 3 chunks
     * @param headerSize the size of the header
     * @param encryptedChunkSize the size of an encrypted chunk
     * @param decrypter the decryption
     */
    private void assertModifiedChunksRejected(byte[] encrypted, int headerSize, int encryptedChunkSize, Decrypter decrypter) {
        // last chunk removed: the data ends at a chunk boundary
        byte[] lastChunkRemoved = Arrays.copyOf(encrypted, encrypted.length - encryptedChunkSize);
        assertThrows(GeneralSecurityException.class, () -> decrypter.decrypt(lastChunkRemoved));

        // first and second chunk swapped
        byte[] swapped = encrypted.clone();
        System.arraycopy(encrypted, headerSize, swapped, headerSize + encryptedChunkSize, encryptedChunkSize);
        System.arraycopy(encrypted, headerSize + encryptedChunkSize, swapped, headerSize, encryptedChunkSize);
        assertThrows(GeneralSecurityException.class, () -> decrypter.decrypt(swapped));

        // additional data after the last chunk
        byte[] appended = Arrays.copyOf(encrypted, encrypted.length + 1);
        assertThrows(GeneralSecurityException.class, () -> decrypter.decrypt(appended));
    }


    /**
     * Create random data.
     *
     * @param size the size
     * @return the data
     */
    private byte[] randomData(int size) {
        byte[] data = new byte[size];
        new SecureRandom().nextBytes(data);
        return data;
    }


    /**
     * Read the stream to the end and close it.
     *
     * @param in the stream
     * @return the content
     * @throws IOException in case of error
     */
    private byte[] readAll(InputStream in) throws IOException {
        try (InputStream input = in) {
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[100];
            int count = input.read(buffer);
            while (count >= 0) {
                result.write(buffer, 0, count);
                count = input.read(buffer);
            }

            return result.toByteArray();
        }
    }


    /**
     * Decrypts data.
     */
    @FunctionalInterface
    private interface Decrypter {
        /**
         * Decrypt the data.
         *
         * @param data the encrypted data
         * @return the decrypted data
         * @throws GeneralSecurityException in case of error
         */
        byte[] decrypt(byte[] data) throws GeneralSecurityException;
    }
}
