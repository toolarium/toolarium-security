/*
 * CryptionOutputStream.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.cryption;

import com.github.toolarium.common.security.ISecuredSecretValue;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;


/**
 * Output stream which encrypts the written content with a {@link CryptionAsymmetric} or a {@link CryptionSymmetric}.
 * The header is written when the stream is created, the content is written chunk by chunk. The stream must be closed,
 * the last chunk is written on {@link #close()}. The result can be decrypted with a {@link CryptionInputStream} or the
 * decrypt methods of the same class.
 *
 * @author patrick
 */
public class CryptionOutputStream extends OutputStream {
    private static final String FAILED_MESSAGE = "The stream is in a failed state after a previous error!";
    private final OutputStream out;
    private final CryptionContext context;
    private final byte[] buffer;
    private final byte[] encrypted;
    private final Cipher cipher;
    private int count;
    private long counter;
    private boolean closed;
    private boolean failed;


    /**
     * Constructor for CryptionOutputStream: encrypt with a public key.
     *
     * @param out the output stream for the encrypted data
     * @param cryption the asymmetric cryption
     * @param publicKey the RSA public key
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    public CryptionOutputStream(OutputStream out, CryptionAsymmetric cryption, PublicKey publicKey) throws GeneralSecurityException, IOException {
        this(out, checkCryption(cryption).createEncryptionContext(publicKey));
    }


    /**
     * Constructor for CryptionOutputStream: encrypt with an AES key.
     *
     * @param out the output stream for the encrypted data
     * @param cryption the symmetric cryption
     * @param key the AES key
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    public CryptionOutputStream(OutputStream out, CryptionSymmetric cryption, SecretKey key) throws GeneralSecurityException, IOException {
        this(out, checkCryption(cryption).createEncryptionContext(key));
    }


    /**
     * Constructor for CryptionOutputStream: encrypt with a key derived from a passphrase.
     *
     * @param out the output stream for the encrypted data
     * @param cryption the symmetric cryption
     * @param passphrase the passphrase
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    public CryptionOutputStream(OutputStream out, CryptionSymmetric cryption, ISecuredSecretValue passphrase) throws GeneralSecurityException, IOException {
        this(out, checkCryption(cryption).createEncryptionContext(passphrase));
    }


    /**
     * Constructor for CryptionOutputStream: encrypt with a key derived from a passphrase.
     *
     * @param out the output stream for the encrypted data
     * @param cryption the symmetric cryption
     * @param passphrase the passphrase, it is not changed
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    public CryptionOutputStream(OutputStream out, CryptionSymmetric cryption, char[] passphrase) throws GeneralSecurityException, IOException {
        this(out, checkCryption(cryption).createEncryptionContext(passphrase));
    }


    /**
     * Constructor for CryptionOutputStream: writes the header.
     *
     * @param out the output stream for the encrypted data
     * @param context the context
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    private CryptionOutputStream(OutputStream out, CryptionContext context) throws GeneralSecurityException, IOException {
        if (out == null) {
            context.destroy();
            throw new IOException("Invalid output stream!");
        }

        this.out = out;
        this.context = context;
        this.buffer = new byte[context.getChunkSize()];
        this.encrypted = new byte[context.getChunkSize() + CryptionStreamSupport.TAG_SIZE];
        this.count = 0;
        this.counter = 0;
        this.closed = false;
        this.failed = false;

        Cipher chunkCipher = null;
        try {
            chunkCipher = CryptionStreamSupport.createCipher(context);
            out.write(context.getHeader());
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            context.destroy();
            throw e;
        }

        this.cipher = chunkCipher;
    }


    /**
     * @see java.io.OutputStream#write(int)
     */
    @Override
    public void write(int b) throws IOException {
        checkNotClosed();
        if (count == buffer.length) {
            writeChunk(false);
        }

        buffer[count++] = (byte) b;
    }


    /**
     * @see java.io.OutputStream#write(byte[], int, int)
     */
    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        checkNotClosed();
        if (b == null) {
            throw new NullPointerException();
        }

        if (off < 0 || len < 0 || len > b.length - off) {
            throw new IndexOutOfBoundsException();
        }

        int position = off;
        int remaining = len;
        while (remaining > 0) {
            if (count == buffer.length) {
                writeChunk(false);
            }

            int length = Math.min(remaining, buffer.length - count);
            System.arraycopy(b, position, buffer, count, length);
            count += length;
            position += length;
            remaining -= length;
        }
    }


    /**
     * Flushes the underlying stream. Content of an incomplete chunk is only written with the next chunk or on
     * {@link #close()}.
     *
     * @see java.io.OutputStream#flush()
     */
    @Override
    public void flush() throws IOException {
        out.flush();
    }


    /**
     * Writes the last chunk and closes the underlying stream. If writing a chunk failed before, no more data is
     * written; the context is destroyed and the underlying stream is closed.
     *
     * @see java.io.OutputStream#close()
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }

        closed = true;
        IOException error = null;
        try {
            if (!failed) {
                writeChunk(true);
                out.flush();
            }
        } catch (IOException e) {
            error = e;
        } finally {
            context.destroy();
            Arrays.fill(buffer, (byte) 0);
            Arrays.fill(encrypted, (byte) 0);
            error = closeOut(error);
        }

        if (error != null) {
            throw error;
        }
    }


    /**
     * Get the length of the encrypted data for the given length of the content: the header, the content and the
     * authentication tag of every chunk. It is an upper bound, it can be one tag longer than the result.
     *
     * @param dataLength the length of the content
     * @return the length of the encrypted data
     */
    long getEncryptedLength(long dataLength) {
        long chunks = dataLength / buffer.length;
        return context.getHeader().length + dataLength + CryptionStreamSupport.TAG_SIZE * (chunks + 1);
    }


    /**
     * Close the underlying stream. An exception of the underlying stream is added as suppressed exception to the
     * given error.
     *
     * @param error the error which occurred before or null
     * @return the error to throw or null
     */
    private IOException closeOut(IOException error) {
        try {
            out.close();
        } catch (IOException e) {
            if (error == null) {
                return e;
            }

            error.addSuppressed(e);
        }

        return error;
    }


    /**
     * Encrypt and write the buffered chunk. After an error the stream is in a failed state and no more chunks are
     * written.
     *
     * @param last true for the last chunk
     * @throws IOException in case of error
     */
    private void writeChunk(boolean last) throws IOException {
        if (failed) {
            throw new IOException(FAILED_MESSAGE);
        }

        boolean success = false;
        try {
            CryptionStreamSupport.initChunkCipher(cipher, Cipher.ENCRYPT_MODE, context, counter, last);
            int length = cipher.doFinal(buffer, 0, count, encrypted, 0);
            out.write(encrypted, 0, length);
            counter++;
            count = 0;
            success = true;
        } catch (GeneralSecurityException e) {
            throw new IOException("Encryption failed: " + e.getMessage(), e);
        } finally {
            if (!success) {
                failed = true;
            }
        }
    }


    /**
     * Check that the stream is not closed and not in a failed state.
     *
     * @throws IOException if the stream is closed or a previous chunk failed
     */
    private void checkNotClosed() throws IOException {
        if (closed) {
            throw new IOException("The stream is closed!");
        }

        if (failed) {
            throw new IOException(FAILED_MESSAGE);
        }
    }


    /**
     * Check the cryption.
     *
     * @param <T> the cryption type
     * @param cryption the cryption
     * @return the cryption
     * @throws GeneralSecurityException if the cryption is null
     */
    private static <T> T checkCryption(T cryption) throws GeneralSecurityException {
        if (cryption == null) {
            throw new GeneralSecurityException("Invalid cryption!");
        }

        return cryption;
    }
}
