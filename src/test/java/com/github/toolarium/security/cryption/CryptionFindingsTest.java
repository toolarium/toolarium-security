/*
 * CryptionFindingsTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.cryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;


/**
 * Test the fixes of the findings N46 to N51 of the cryption streams.
 *
 * @author patrick
 */
public class CryptionFindingsTest {
    private static final int CHUNK_SIZE = 1024;
    private static final int TAG_SIZE = 16;
    private static final int KEY_HEADER_SIZE = 32;
    private static final int ITERATIONS = 1000;
    private static final String PASSPHRASE = "my-secret-passphrase";
    private static final String WRITE_FAILED = "write failed";
    private static final String CLOSE_FAILED = "close failed";


    /**
     * Constructor for CryptionFindingsTest
     */
    public CryptionFindingsTest() {
        // NOP
    }


    /**
     * N46: after a failed chunk every further read of the input stream fails again.
     *
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    @Test
    public void testInputStreamFailedStateIsLatched() throws GeneralSecurityException, IOException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().chunkSize(CHUNK_SIZE).build();
        SecretKey key = cryption.generateKey();
        byte[] data = randomBytes(CHUNK_SIZE * 3 + 10);
        byte[] encrypted = cryption.encrypt(key, data);

        // modify the second chunk
        encrypted[KEY_HEADER_SIZE + CHUNK_SIZE + TAG_SIZE + 5] ^= 1;

        try (CryptionInputStream in = cryption.createInputStream(new ByteArrayInputStream(encrypted), key)) {
            byte[] buffer = new byte[CHUNK_SIZE];
            assertEquals(CHUNK_SIZE, in.read(buffer));

            IOException e = assertThrows(IOException.class, () -> in.read(buffer));
            assertTrue(e.getCause() instanceof GeneralSecurityException);

            // later reads fail as well, they do not continue with the next chunk
            IOException next = assertThrows(IOException.class, () -> in.read(buffer));
            assertTrue(next.getCause() instanceof GeneralSecurityException);
            assertThrows(IOException.class, () -> in.read());
            assertThrows(IOException.class, () -> in.read(buffer, 0, buffer.length));
        }
    }


    /**
     * N46: after a failed chunk the output stream writes no more data, close still closes the underlying stream.
     *
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    @Test
    public void testOutputStreamFailedStateIsLatched() throws GeneralSecurityException, IOException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().chunkSize(CHUNK_SIZE).build();
        TestOutputStream target = new TestOutputStream();
        CryptionOutputStream out = cryption.createOutputStream(target, cryption.generateKey());
        assertEquals(KEY_HEADER_SIZE, target.size());

        target.failWrite = true;
        IOException e = assertThrows(IOException.class, () -> out.write(new byte[CHUNK_SIZE * 2]));
        assertEquals(WRITE_FAILED, e.getMessage());

        // the underlying stream works again, but the encrypting stream stays in the failed state
        target.failWrite = false;
        assertThrows(IOException.class, () -> out.write(1));
        assertThrows(IOException.class, () -> out.write(new byte[10]));
        out.close();
        assertEquals(KEY_HEADER_SIZE, target.size());
        assertTrue(target.closed);
    }


    /**
     * N49: a failure while the header is written is reported.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testHeaderWriteFailure() throws GeneralSecurityException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().chunkSize(CHUNK_SIZE).build();
        SecretKey key = cryption.generateKey();
        TestOutputStream target = new TestOutputStream();
        target.failWrite = true;
        IOException e = assertThrows(IOException.class, () -> cryption.createOutputStream(target, key));
        assertEquals(WRITE_FAILED, e.getMessage());
    }


    /**
     * N50: the error of the last chunk is kept on close, the error of the underlying close is added as suppressed.
     *
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    @Test
    public void testCloseKeepsFirstException() throws GeneralSecurityException, IOException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().chunkSize(CHUNK_SIZE).build();
        TestOutputStream target = new TestOutputStream();
        CryptionOutputStream out = cryption.createOutputStream(target, cryption.generateKey());
        out.write(new byte[10]);

        target.failWrite = true;
        target.failClose = true;
        IOException e = assertThrows(IOException.class, () -> out.close());
        assertEquals(WRITE_FAILED, e.getMessage());
        assertEquals(1, e.getSuppressed().length);
        assertEquals(CLOSE_FAILED, e.getSuppressed()[0].getMessage());
    }


    /**
     * N50: if only the underlying close fails, its exception is thrown.
     *
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    @Test
    public void testCloseException() throws GeneralSecurityException, IOException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().chunkSize(CHUNK_SIZE).build();
        TestOutputStream target = new TestOutputStream();
        CryptionOutputStream out = cryption.createOutputStream(target, cryption.generateKey());
        target.failClose = true;
        IOException e = assertThrows(IOException.class, () -> out.close());
        assertEquals(CLOSE_FAILED, e.getMessage());
        assertEquals(KEY_HEADER_SIZE + TAG_SIZE, target.size());
    }


    /**
     * N47: the key specification is created once per context and not available after destroy.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testKeySpecPerContext() throws GeneralSecurityException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().chunkSize(CHUNK_SIZE).build();
        CryptionContext context = cryption.createEncryptionContext(cryption.generateKey());
        assertSame(context.getKeySpec(), context.getKeySpec());
        context.destroy();
        assertThrows(IllegalStateException.class, () -> context.getKeySpec());
    }


    /**
     * N51: one cipher per stream gives the same format; the length of the encrypted data is header, data and one tag
     * per chunk.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testEncryptedLengthAndRoundTrip() throws GeneralSecurityException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().chunkSize(CHUNK_SIZE).build();
        SecretKey key = cryption.generateKey();
        int[] sizes = {0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, CHUNK_SIZE * 5 + 7};
        for (int size : sizes) {
            byte[] data = randomBytes(size);
            int chunks = Math.max(1, (size + CHUNK_SIZE - 1) / CHUNK_SIZE);
            byte[] encrypted = cryption.encrypt(key, data);
            assertEquals(KEY_HEADER_SIZE + size + TAG_SIZE * chunks, encrypted.length);
            assertArrayEquals(data, cryption.decrypt(key, encrypted));

            ByteArrayOutputStream streamResult = new ByteArrayOutputStream();
            try (CryptionOutputStream out = cryption.createOutputStream(streamResult, key)) {
                for (byte b : data) {
                    out.write(b);
                }
            } catch (IOException e) {
                throw new GeneralSecurityException(e);
            }

            assertArrayEquals(data, cryption.decrypt(key, streamResult.toByteArray()));
        }
    }


    /**
     * N48: the PBKDF2 key derivation uses the configured provider.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testPassphraseWithProvider() throws GeneralSecurityException {
        CryptionSymmetric cryption = CryptionSymmetric.builder().provider("SunJCE").iterations(ITERATIONS).chunkSize(CHUNK_SIZE).build();
        byte[] data = PASSPHRASE.getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(data, cryption.decrypt(PASSPHRASE.toCharArray(), cryption.encrypt(PASSPHRASE.toCharArray(), data)));

        CryptionSymmetric unknownProvider = CryptionSymmetric.builder().provider("UnknownProvider").iterations(ITERATIONS).build();
        assertThrows(GeneralSecurityException.class, () -> unknownProvider.encrypt(PASSPHRASE.toCharArray(), data));
    }


    /**
     * N35: data with more PBKDF2 iterations than the accepted maximum is rejected before the key is derived.
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testMaxIterations() throws GeneralSecurityException {
        byte[] data = PASSPHRASE.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = CryptionSymmetric.builder().iterations(ITERATIONS * 2).build().encrypt(PASSPHRASE.toCharArray(), data);

        // the maximum is lower than the iterations of the data
        CryptionSymmetric limited = CryptionSymmetric.builder().iterations(ITERATIONS).maxIterations(ITERATIONS).build();
        assertThrows(GeneralSecurityException.class, () -> limited.decrypt(PASSPHRASE.toCharArray(), encrypted));

        // the default maximum and a higher maximum accept the data
        assertArrayEquals(data, CryptionSymmetric.getInstance().decrypt(PASSPHRASE.toCharArray(), encrypted));
        assertArrayEquals(data, CryptionSymmetric.builder().maxIterations(ITERATIONS * 2).iterations(ITERATIONS).build().decrypt(PASSPHRASE.toCharArray(), encrypted));

        // more than twice the default iterations are rejected by the default instance
        byte[] manyIterations = CryptionSymmetric.builder().iterations(CryptionSymmetric.DEFAULT_ITERATIONS * 2 + 1).build().encrypt(PASSPHRASE.toCharArray(), new byte[0]);
        assertThrows(GeneralSecurityException.class, () -> CryptionSymmetric.getInstance().decrypt(PASSPHRASE.toCharArray(), manyIterations));

        // invalid builder settings
        assertThrows(IllegalArgumentException.class, () -> CryptionSymmetric.builder().maxIterations(0));
        assertThrows(IllegalArgumentException.class, () -> CryptionSymmetric.builder().maxIterations(CryptionSymmetric.MAX_ITERATIONS + 1));
        assertThrows(IllegalArgumentException.class, () -> CryptionSymmetric.builder().iterations(ITERATIONS * 2).maxIterations(ITERATIONS).build());
    }


    /**
     * Create random bytes.
     *
     * @param length the length
     * @return the random bytes
     */
    private static byte[] randomBytes(int length) {
        byte[] result = new byte[length];
        new SecureRandom().nextBytes(result);
        return result;
    }


    /**
     * Output stream which can fail on write and close.
     */
    private static final class TestOutputStream extends OutputStream {
        private final ByteArrayOutputStream content = new ByteArrayOutputStream();
        private boolean failWrite;
        private boolean failClose;
        private boolean closed;


        /**
         * @see java.io.OutputStream#write(int)
         */
        @Override
        public void write(int b) throws IOException {
            checkWrite();
            content.write(b);
        }


        /**
         * @see java.io.OutputStream#write(byte[], int, int)
         */
        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            checkWrite();
            content.write(b, off, len);
        }


        /**
         * @see java.io.OutputStream#close()
         */
        @Override
        public void close() throws IOException {
            closed = true;
            if (failClose) {
                throw new IOException(CLOSE_FAILED);
            }
        }


        /**
         * Get the number of written bytes.
         *
         * @return the number of written bytes
         */
        int size() {
            return content.size();
        }


        /**
         * Check if writing is allowed.
         *
         * @throws IOException if writing fails
         */
        private void checkWrite() throws IOException {
            if (failWrite) {
                throw new IOException(WRITE_FAILED);
            }
        }
    }
}
