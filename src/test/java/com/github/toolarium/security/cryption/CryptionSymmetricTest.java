/*
 * CryptionSymmetricTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.cryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.common.ByteArray;
import com.github.toolarium.common.security.ISecuredSecretValue;
import com.github.toolarium.common.security.SecuredValueFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;


/**
 * Test the {@link CryptionSymmetric}.
 *
 * @author patrick
 */
public class CryptionSymmetricTest {
    private static final String TEXT = "Hello world, äöü €!";
    private static final String SIZE = "size ";
    private static final int CHUNK_SIZE = 1024;
    private static final int CHUNK_SIZE_POSITION = 4;
    private static final int TAG_SIZE = 16;
    private static final int[] STREAM_SIZES = {0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, CHUNK_SIZE * 2, CHUNK_SIZE * 5 + 7};
    private static final String PASSPHRASE = "my-secret-passphrase";
    private static final int SOURCE_POSITION = 8;
    private static final int AES_KEY_SIZE_POSITION = 9;
    private static final int ITERATIONS_POSITION = 10;
    private static final int KEY_HEADER_SIZE = 32;
    private static final int PASSPHRASE_HEADER_SIZE = 37;
    private static final int ITERATIONS = 1000;


    /**
     * Constructor for CryptionSymmetricTest
     */
    public CryptionSymmetricTest() {
        // NOP
    }


    /**
     * Encrypt and decrypt with an AES key: bytes, a {@link ByteArray} and a text.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testKeyRoundTrip() throws GeneralSecurityException {
        CryptionSymmetric cryption = CryptionSymmetric.getInstance();
        SecretKey key = cryption.generateKey();
        assertEquals(32, key.getEncoded().length);
        byte[] data = TEXT.getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = cryption.encrypt(key, data);
        assertTrue(cryption.isEncrypted(encrypted));
        assertEquals(1, encrypted[SOURCE_POSITION]);
        assertArrayEquals(data, cryption.decrypt(key, encrypted));
        assertArrayEquals(data, cryption.decrypt(key, cryption.encrypt(key, new ByteArray(data))).toBytes());
        assertEquals(TEXT, cryption.decrypt(key, cryption.encrypt(key, TEXT)));

        // empty and large data
        assertArrayEquals(new byte[0], cryption.decrypt(key, cryption.encrypt(key, new byte[0])));
        byte[] largeData = new byte[1024 * 1024];
        new SecureRandom().nextBytes(largeData);
        assertArrayEquals(largeData, cryption.decrypt(key, cryption.encrypt(key, largeData)));
    }


    /**
     * Encrypt and decrypt with a passphrase: char array, {@link ISecuredSecretValue}, bytes, {@link ByteArray} and text.
     * The passphrase array is not changed.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testPassphraseRoundTrip() throws GeneralSecurityException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().iterations(ITERATIONS).build();
        char[] passphrase = PASSPHRASE.toCharArray();
        byte[] data = TEXT.getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = cryption.encrypt(passphrase, data);
        assertArrayEquals(PASSPHRASE.toCharArray(), passphrase);
        assertTrue(cryption.isEncrypted(encrypted));
        assertEquals(2, encrypted[SOURCE_POSITION]);
        assertArrayEquals(data, cryption.decrypt(passphrase, encrypted));
        assertArrayEquals(PASSPHRASE.toCharArray(), passphrase);
        assertArrayEquals(data, cryption.decrypt(passphrase, cryption.encrypt(passphrase, new ByteArray(data))).toBytes());
        assertEquals(TEXT, cryption.decrypt(passphrase, cryption.encrypt(passphrase, TEXT)));

        ISecuredSecretValue securedPassphrase = SecuredValueFactory.getInstance().createSecret(PASSPHRASE.toCharArray(), "...");
        assertArrayEquals(data, cryption.decrypt(securedPassphrase, cryption.encrypt(securedPassphrase, data)));
        assertArrayEquals(data, cryption.decrypt(securedPassphrase, cryption.encrypt(securedPassphrase, new ByteArray(data))).toBytes());
        assertEquals(TEXT, cryption.decrypt(securedPassphrase, cryption.encrypt(securedPassphrase, TEXT)));

        // char array and secured value are interchangeable
        assertArrayEquals(data, cryption.decrypt(securedPassphrase, encrypted));
    }


    /**
     * Every encryption uses a new IV (and a new salt for a passphrase), the result differs for the same data.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testDifferentResultPerEncryption() throws GeneralSecurityException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().iterations(ITERATIONS).build();
        SecretKey key = cryption.generateKey();
        byte[] data = TEXT.getBytes(StandardCharsets.UTF_8);
        assertFalse(Arrays.equals(cryption.encrypt(key, data), cryption.encrypt(key, data)));
        assertFalse(Arrays.equals(cryption.encrypt(PASSPHRASE.toCharArray(), data), cryption.encrypt(PASSPHRASE.toCharArray(), data)));
    }


    /**
     * Streams: the stream and the byte methods use the same format, with an AES key, a char array and a secured
     * passphrase, with the constructors and the factory methods, for empty data, data smaller than a chunk, exactly one
     * and two chunks and more than two chunks.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testStreamRoundTrip() throws Exception {
        CryptionSymmetric cryption = CryptionSymmetric.builder().chunkSize(CHUNK_SIZE).iterations(ITERATIONS).build();
        SecretKey key = cryption.generateKey();
        ISecuredSecretValue securedPassphrase = SecuredValueFactory.getInstance().createSecret(PASSPHRASE.toCharArray(), "...");

        for (int size : STREAM_SIZES) {
            byte[] data = randomData(size);

            ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
            try (CryptionOutputStream out = new CryptionOutputStream(encrypted, cryption, key)) {
                out.write(data);
            }
            assertTrue(cryption.isEncrypted(encrypted.toByteArray()));
            assertArrayEquals(data, cryption.decrypt(key, encrypted.toByteArray()), SIZE + size);
            assertArrayEquals(data, readAll(cryption.createInputStream(new ByteArrayInputStream(cryption.encrypt(key, data)), key)), SIZE + size);

            encrypted = new ByteArrayOutputStream();
            try (CryptionOutputStream out = cryption.createOutputStream(encrypted, PASSPHRASE.toCharArray())) {
                out.write(data);
            }
            assertArrayEquals(data, cryption.decrypt(securedPassphrase, encrypted.toByteArray()), SIZE + size);
            assertArrayEquals(data, readAll(new CryptionInputStream(new ByteArrayInputStream(encrypted.toByteArray()), cryption, securedPassphrase)), SIZE + size);

            encrypted = new ByteArrayOutputStream();
            try (CryptionOutputStream out = new CryptionOutputStream(encrypted, cryption, securedPassphrase)) {
                out.write(data);
            }
            assertArrayEquals(data, readAll(new CryptionInputStream(new ByteArrayInputStream(encrypted.toByteArray()), cryption, PASSPHRASE.toCharArray())), SIZE + size);
            assertArrayEquals(data, readAll(cryption.createInputStream(new ByteArrayInputStream(cryption.encrypt(securedPassphrase, data)), PASSPHRASE.toCharArray())), SIZE + size);
        }
    }


    /**
     * Streams: single bytes can be written and read.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testStreamSingleBytes() throws Exception {
        CryptionSymmetric cryption = CryptionSymmetric.builder().chunkSize(CHUNK_SIZE).build();
        SecretKey key = cryption.generateKey();
        byte[] data = randomData(CHUNK_SIZE * 2 + 5);

        ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
        try (CryptionOutputStream out = cryption.createOutputStream(encrypted, key)) {
            for (byte b : data) {
                out.write(b);
            }
        }

        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        try (CryptionInputStream in = cryption.createInputStream(new ByteArrayInputStream(encrypted.toByteArray()), key)) {
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
        CryptionSymmetric cryption = CryptionSymmetric.builder().chunkSize(CHUNK_SIZE).build();
        SecretKey key = cryption.generateKey();
        byte[] encrypted = cryption.encrypt(key, randomData(CHUNK_SIZE * 3));
        int encryptedChunkSize = CHUNK_SIZE + TAG_SIZE;
        assertEquals(KEY_HEADER_SIZE + 3 * encryptedChunkSize, encrypted.length);
        assertModifiedChunksRejected(encrypted, KEY_HEADER_SIZE, encryptedChunkSize, data -> cryption.decrypt(key, data));

        byte[] lastChunkRemoved = Arrays.copyOf(encrypted, encrypted.length - encryptedChunkSize);
        try (InputStream in = cryption.createInputStream(new ByteArrayInputStream(lastChunkRemoved), key)) {
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
        assertEquals(CryptionSymmetric.DEFAULT_CHUNK_SIZE, CryptionSymmetric.getInstance().getChunkSize());
        assertEquals(CHUNK_SIZE, CryptionSymmetric.builder().chunkSize(CHUNK_SIZE).build().getChunkSize());
        assertThrows(IllegalArgumentException.class, () -> CryptionSymmetric.builder().chunkSize(CryptionSymmetric.MIN_CHUNK_SIZE - 1));
        assertThrows(IllegalArgumentException.class, () -> CryptionSymmetric.builder().chunkSize(CryptionSymmetric.MAX_CHUNK_SIZE + 1));

        SecretKey key = CryptionSymmetric.getInstance().generateKey();
        byte[] data = randomData(CHUNK_SIZE * 3);
        byte[] encrypted = CryptionSymmetric.builder().chunkSize(CHUNK_SIZE).build().encrypt(key, data);
        assertEquals(CHUNK_SIZE, ByteBuffer.wrap(encrypted).getInt(CHUNK_SIZE_POSITION));
        assertArrayEquals(data, CryptionSymmetric.getInstance().decrypt(key, encrypted));

        ByteBuffer.wrap(encrypted).putInt(CHUNK_SIZE_POSITION, Integer.MAX_VALUE);
        assertThrows(GeneralSecurityException.class, () -> CryptionSymmetric.getInstance().decrypt(key, encrypted));
    }


    /**
     * Streams: invalid arguments of the constructors are rejected.
     */
    @Test
    public void testStreamInvalidArguments() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        SecretKey key = CryptionSymmetric.getInstance().generateKey();
        assertThrows(GeneralSecurityException.class, () -> new CryptionOutputStream(out, (CryptionSymmetric) null, key));
        assertThrows(GeneralSecurityException.class, () -> new CryptionOutputStream(out, CryptionSymmetric.getInstance(), (SecretKey) null));
        assertThrows(GeneralSecurityException.class, () -> new CryptionOutputStream(out, CryptionSymmetric.getInstance(), (char[]) null));
        assertThrows(GeneralSecurityException.class, () -> new CryptionOutputStream(out, CryptionSymmetric.getInstance(), (ISecuredSecretValue) null));
        assertThrows(IOException.class, () -> new CryptionOutputStream(null, CryptionSymmetric.getInstance(), key));
        assertThrows(IOException.class, () -> new CryptionInputStream(null, CryptionSymmetric.getInstance(), key));
        assertThrows(GeneralSecurityException.class, () -> new CryptionInputStream(new ByteArrayInputStream(new byte[] {1, 2, 3}), CryptionSymmetric.getInstance(), key));
    }


    /**
     * Streams: the key of the context is destroyed when the stream is closed and can not be used anymore.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testStreamContextDestroyed() throws Exception {
        SecretKey key = CryptionSymmetric.getInstance().generateKey();
        CryptionContext context = CryptionSymmetric.getInstance().createEncryptionContext(key);
        assertFalse(context.isDestroyed());
        context.destroy();
        assertTrue(context.isDestroyed());
        assertThrows(IllegalStateException.class, () -> context.getKey());

        CryptionOutputStream out = CryptionSymmetric.getInstance().createOutputStream(new ByteArrayOutputStream(), key);
        out.close();
        assertThrows(IOException.class, () -> out.write(1));
    }


    /**
     * The builder: the settings are stored in the encrypted data and every instance can decrypt the data of an other
     * instance.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testBuilder() throws GeneralSecurityException {
        CryptionSymmetric defaultCryption = CryptionSymmetric.getInstance();
        assertNull(defaultCryption.getProvider());
        assertEquals(CryptionSymmetric.AesKeySize.AES_256, defaultCryption.getAesKeySize());
        assertEquals(CryptionSymmetric.DEFAULT_ITERATIONS, defaultCryption.getIterations());

        byte[] data = TEXT.getBytes(StandardCharsets.UTF_8);
        for (CryptionSymmetric.AesKeySize aesKeySize : CryptionSymmetric.AesKeySize.values()) {
            CryptionSymmetric cryption = CryptionSymmetric.builder().provider("SunJCE").aesKeySize(aesKeySize).iterations(ITERATIONS).build();
            assertEquals("SunJCE", cryption.getProvider());
            assertEquals(aesKeySize, cryption.getAesKeySize());
            assertEquals(ITERATIONS, cryption.getIterations());

            SecretKey key = cryption.generateKey();
            assertEquals((aesKeySize.ordinal() + 2) * 8, key.getEncoded().length);
            assertArrayEquals(data, defaultCryption.decrypt(key, cryption.encrypt(key, data)), aesKeySize.toString());

            byte[] encrypted = cryption.encrypt(PASSPHRASE.toCharArray(), data);
            assertEquals(aesKeySize.ordinal() + 1, encrypted[AES_KEY_SIZE_POSITION]);
            assertEquals(ITERATIONS, ByteBuffer.wrap(encrypted, ITERATIONS_POSITION, 4).getInt());
            assertArrayEquals(data, defaultCryption.decrypt(PASSPHRASE.toCharArray(), encrypted), aesKeySize.toString());
        }

        assertThrows(IllegalArgumentException.class, () -> CryptionSymmetric.builder().aesKeySize(null));
        assertThrows(IllegalArgumentException.class, () -> CryptionSymmetric.builder().iterations(0));
        assertThrows(IllegalArgumentException.class, () -> CryptionSymmetric.builder().iterations(CryptionSymmetric.MAX_ITERATIONS + 1));

        CryptionSymmetric unknownProvider = CryptionSymmetric.builder().provider("UnknownProvider").build();
        assertThrows(GeneralSecurityException.class, () -> unknownProvider.encrypt(unknownProvider.generateKey(), data));
    }


    /**
     * Modified or truncated data is rejected.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testModifiedData() throws GeneralSecurityException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().iterations(ITERATIONS).build();
        SecretKey key = cryption.generateKey();
        byte[] data = TEXT.getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = cryption.encrypt(key, data);
        int[] positions = {encrypted.length - 1, KEY_HEADER_SIZE, KEY_HEADER_SIZE + 12};
        for (int position : positions) {
            byte[] modified = encrypted.clone();
            modified[position] ^= 1;
            assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(key, modified), "position " + position);
        }
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(key, Arrays.copyOf(encrypted, encrypted.length - 1)));
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(key, Arrays.copyOf(encrypted, KEY_HEADER_SIZE + 10)));

        byte[] encryptedWithPassphrase = cryption.encrypt(PASSPHRASE.toCharArray(), data);
        int[] passphrasePositions = {encryptedWithPassphrase.length - 1, AES_KEY_SIZE_POSITION, ITERATIONS_POSITION + 3, PASSPHRASE_HEADER_SIZE - 1};
        for (int position : passphrasePositions) {
            byte[] modified = encryptedWithPassphrase.clone();
            modified[position] ^= 1;
            assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(PASSPHRASE.toCharArray(), modified), "position " + position);
        }
    }


    /**
     * A wrong key, a wrong passphrase and the wrong key source are rejected.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testWrongKey() throws GeneralSecurityException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().iterations(ITERATIONS).build();
        SecretKey key = cryption.generateKey();
        byte[] data = TEXT.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = cryption.encrypt(key, data);
        byte[] encryptedWithPassphrase = cryption.encrypt(PASSPHRASE.toCharArray(), data);

        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(cryption.generateKey(), encrypted));
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt("wrong".toCharArray(), encryptedWithPassphrase));
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(PASSPHRASE.toCharArray(), encrypted));
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(key, encryptedWithPassphrase));
    }


    /**
     * Invalid keys, passphrases and data are rejected, too many iterations in the data as well.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testInvalidInput() throws GeneralSecurityException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().iterations(ITERATIONS).build();
        byte[] data = TEXT.getBytes(StandardCharsets.UTF_8);

        assertThrows(GeneralSecurityException.class, () -> cryption.encrypt((SecretKey) null, data));
        assertThrows(GeneralSecurityException.class, () -> cryption.encrypt(new SecretKeySpec(new byte[16], "DES"), data));
        assertThrows(GeneralSecurityException.class, () -> cryption.encrypt(new SecretKeySpec(new byte[10], "AES"), data));
        assertThrows(GeneralSecurityException.class, () -> cryption.encrypt((char[]) null, data));
        assertThrows(GeneralSecurityException.class, () -> cryption.encrypt((ISecuredSecretValue) null, data));
        assertThrows(GeneralSecurityException.class, () -> cryption.encrypt(cryption.generateKey(), (byte[]) null));
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(cryption.generateKey(), (byte[]) null));
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(cryption.generateKey(), "no base64!"));

        byte[] encrypted = cryption.encrypt(PASSPHRASE.toCharArray(), data);
        ByteBuffer.wrap(encrypted).putInt(ITERATIONS_POSITION, Integer.MAX_VALUE);
        assertThrows(GeneralSecurityException.class, () -> cryption.decrypt(PASSPHRASE.toCharArray(), encrypted));
    }


    /**
     * The marker and the format version are detected.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testIsEncrypted() throws GeneralSecurityException {
        CryptionSymmetric cryption = CryptionSymmetric.getInstance();
        byte[] encrypted = cryption.encrypt(cryption.generateKey(), TEXT.getBytes(StandardCharsets.UTF_8));
        assertEquals('T', encrypted[0]);
        assertEquals('C', encrypted[1]);
        assertEquals('S', encrypted[2]);
        assertEquals(1, encrypted[3]);

        assertFalse(cryption.isEncrypted((byte[]) null));
        assertFalse(cryption.isEncrypted((String) null));
        assertFalse(cryption.isEncrypted(TEXT.getBytes(StandardCharsets.UTF_8)));
        assertFalse(cryption.isEncrypted("no base64!"));

        byte[] otherVersion = encrypted.clone();
        otherVersion[3] = 2;
        assertFalse(cryption.isEncrypted(otherVersion));
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
