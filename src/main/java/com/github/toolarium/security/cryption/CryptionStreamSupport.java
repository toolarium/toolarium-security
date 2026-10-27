/*
 * CryptionStreamSupport.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.cryption;

import com.github.toolarium.security.cryption.util.CryptionUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;


/**
 * Common parts of the chunked AES-GCM format of {@link CryptionAsymmetric} and {@link CryptionSymmetric}.
 *
 * <p>The content is split into chunks of the chunk size. Every chunk is encrypted with AES-GCM and its own nonce: the
 * nonce prefix of the header, the chunk counter (4 bytes) and a flag for the last chunk (1 byte). The header is
 * authenticated with every chunk. Chunks can not be reordered, removed or cut off without being detected.</p>
 *
 * @author patrick
 */
final class CryptionStreamSupport {
    /** The default chunk size: 64 KB */
    static final int DEFAULT_CHUNK_SIZE = 64 * 1024;

    /** The minimum chunk size: 1 KB */
    static final int MIN_CHUNK_SIZE = 1024;

    /** The maximum chunk size: 16 MB */
    static final int MAX_CHUNK_SIZE = 16 * 1024 * 1024;

    /** The size of the nonce prefix at the end of the header */
    static final int NONCE_PREFIX_SIZE = 7;

    /** The size of the authentication tag of a chunk */
    static final int TAG_SIZE = 16;

    /** The message for invalid encrypted data */
    static final String INVALID_DATA = "Invalid encrypted data!";

    /** The secure random */
    static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final int NONCE_SIZE = 12;
    private static final long MAX_CHUNKS = 0xFFFFFFFFL;
    private static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";


    /**
     * Constructor
     */
    private CryptionStreamSupport() {
        // NOP
    }


    /**
     * Create a stream which encrypts.
     */
    @FunctionalInterface
    interface OutputStreamFactory {
        /**
         * Create the stream.
         *
         * @param out the output stream for the encrypted data
         * @return the encrypting stream
         * @throws GeneralSecurityException in case of error
         * @throws IOException in case of an I/O error
         */
        CryptionOutputStream create(OutputStream out) throws GeneralSecurityException, IOException;
    }


    /**
     * Create a stream which decrypts.
     */
    @FunctionalInterface
    interface InputStreamFactory {
        /**
         * Create the stream.
         *
         * @param in the input stream of the encrypted data
         * @return the decrypting stream
         * @throws GeneralSecurityException in case of error
         * @throws IOException in case of an I/O error
         */
        CryptionInputStream create(InputStream in) throws GeneralSecurityException, IOException;
    }


    /**
     * Check the chunk size.
     *
     * @param chunkSize the chunk size
     * @return true if the chunk size is valid
     */
    static boolean isValidChunkSize(int chunkSize) {
        return chunkSize >= MIN_CHUNK_SIZE && chunkSize <= MAX_CHUNK_SIZE;
    }


    /**
     * Create a new random byte array.
     *
     * @param length the length
     * @return the random bytes
     */
    static byte[] randomBytes(int length) {
        byte[] result = new byte[length];
        SECURE_RANDOM.nextBytes(result);
        return result;
    }


    /**
     * Create the cipher of a stream. It is created once per stream and initialised for every chunk with
     * {@link #initChunkCipher(Cipher, int, CryptionContext, long, boolean)}.
     *
     * @param context the context
     * @return the cipher
     * @throws GeneralSecurityException in case of error
     */
    static Cipher createCipher(CryptionContext context) throws GeneralSecurityException {
        return CryptionUtil.getInstance().getCipher(context.getProvider(), AES_ALGORITHM);
    }


    /**
     * Initialise the cipher for one chunk.
     *
     * @param cipher the cipher of the stream
     * @param mode the cipher mode
     * @param context the context
     * @param counter the chunk counter
     * @param last true for the last chunk
     * @throws GeneralSecurityException in case of error
     */
    static void initChunkCipher(Cipher cipher, int mode, CryptionContext context, long counter, boolean last) throws GeneralSecurityException {
        if (counter > MAX_CHUNKS) {
            throw new GeneralSecurityException("Too many chunks!");
        }

        byte[] header = context.getHeader();
        byte lastFlag = 0;
        if (last) {
            lastFlag = 1;
        }

        ByteBuffer nonce = ByteBuffer.allocate(NONCE_SIZE);
        nonce.put(header, header.length - NONCE_PREFIX_SIZE, NONCE_PREFIX_SIZE).putInt((int) counter).put(lastFlag);

        cipher.init(mode, context.getKeySpec(), new GCMParameterSpec(TAG_SIZE * 8, nonce.array()));
        cipher.updateAAD(header);
    }


    /**
     * Read exactly the given number of bytes.
     *
     * @param in the input stream
     * @param length the number of bytes
     * @return the bytes
     * @throws IOException in case of an I/O error
     * @throws GeneralSecurityException if the stream ends before
     */
    static byte[] readHeader(InputStream in, int length) throws IOException, GeneralSecurityException {
        byte[] result = new byte[length];
        if (read(in, result, 0, length) != length) {
            throw new GeneralSecurityException(INVALID_DATA);
        }

        return result;
    }


    /**
     * Read until the buffer is full or the stream ends.
     *
     * @param in the input stream
     * @param buffer the buffer
     * @param offset the offset
     * @param length the number of bytes
     * @return the number of read bytes
     * @throws IOException in case of an I/O error
     */
    static int read(InputStream in, byte[] buffer, int offset, int length) throws IOException {
        int total = 0;
        while (total < length) {
            int count = in.read(buffer, offset + total, length - total);
            if (count < 0) {
                break;
            }

            total += count;
        }

        return total;
    }


    /**
     * Concat two byte arrays.
     *
     * @param first the first array
     * @param second the second array
     * @return the concatenated array
     */
    static byte[] concat(byte[] first, byte[] second) {
        return ByteBuffer.allocate(first.length + second.length).put(first).put(second).array();
    }


    /**
     * Encrypt data with a stream.
     *
     * @param factory the factory of the encrypting stream
     * @param data the data
     * @return the encrypted data
     * @throws GeneralSecurityException in case of error
     */
    static byte[] encrypt(OutputStreamFactory factory, byte[] data) throws GeneralSecurityException {
        if (data == null) {
            throw new GeneralSecurityException("Invalid data!");
        }

        ResultOutputStream result = new ResultOutputStream(0);
        try (CryptionOutputStream out = factory.create(result)) {
            result.reserve(out.getEncryptedLength(data.length));
            out.write(data);
        } catch (IOException e) {
            throw toGeneralSecurityException(e);
        }

        return result.toResult();
    }


    /**
     * Decrypt data with a stream.
     *
     * @param factory the factory of the decrypting stream
     * @param data the encrypted data
     * @return the decrypted data
     * @throws GeneralSecurityException in case of error
     */
    static byte[] decrypt(InputStreamFactory factory, byte[] data) throws GeneralSecurityException {
        if (data == null) {
            throw new GeneralSecurityException(INVALID_DATA);
        }

        ResultOutputStream result = new ResultOutputStream(data.length);
        byte[] buffer = new byte[8192];
        try (CryptionInputStream in = factory.create(new ByteArrayInputStream(data))) {
            int count = in.read(buffer);
            while (count >= 0) {
                result.write(buffer, 0, count);
                count = in.read(buffer);
            }
        } catch (IOException e) {
            result.clear();
            throw toGeneralSecurityException(e);
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }

        return result.toResult();
    }


    /**
     * Convert an I/O error of a stream into a {@link GeneralSecurityException}.
     *
     * @param e the I/O error
     * @return the exception
     */
    static GeneralSecurityException toGeneralSecurityException(IOException e) {
        if (e.getCause() instanceof GeneralSecurityException) {
            return (GeneralSecurityException) e.getCause();
        }

        return new GeneralSecurityException(INVALID_DATA, e);
    }


    /**
     * Decode a Base64 string.
     *
     * @param base64Data the Base64 string
     * @return the decoded data or null if it is no valid Base64 string
     */
    static byte[] decodeBase64(String base64Data) {
        if (base64Data == null) {
            return null;
        }

        try {
            return Base64.getDecoder().decode(base64Data.trim());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }


    /**
     * Byte array output stream for the result of {@link CryptionStreamSupport#encrypt(OutputStreamFactory, byte[])} and
     * {@link CryptionStreamSupport#decrypt(InputStreamFactory, byte[])}: the buffer can be reserved in advance and it is
     * cleared after use.
     */
    private static final class ResultOutputStream extends ByteArrayOutputStream {
        /**
         * Constructor for ResultOutputStream
         *
         * @param size the initial size
         */
        ResultOutputStream(int size) {
            super(size);
        }


        /**
         * Make sure the buffer has at least the given capacity.
         *
         * @param capacity the capacity
         */
        synchronized void reserve(long capacity) {
            if (capacity > buf.length && capacity <= MAX_ARRAY_SIZE) {
                buf = Arrays.copyOf(buf, (int) capacity);
            }
        }


        /**
         * Get the result. If the buffer is filled exactly it is returned without a copy, otherwise a copy is returned
         * and the buffer is cleared.
         *
         * @return the result
         */
        synchronized byte[] toResult() {
            if (count == buf.length) {
                return buf;
            }

            byte[] result = Arrays.copyOf(buf, count);
            clear();
            return result;
        }


        /**
         * Clear the buffer.
         */
        synchronized void clear() {
            Arrays.fill(buf, (byte) 0);
            count = 0;
        }
    }
}
