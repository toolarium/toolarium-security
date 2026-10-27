/*
 * CryptionInputStream.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.cryption;

import com.github.toolarium.common.security.ISecuredSecretValue;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;


/**
 * Input stream which decrypts content of a {@link CryptionAsymmetric} or a {@link CryptionSymmetric}, written by a
 * {@link CryptionOutputStream} or the encrypt methods of the same class. The header is read when the stream is
 * created, the content is decrypted chunk by chunk. Only verified content is returned; modified, reordered or
 * truncated data gives an {@link IOException} with a {@link GeneralSecurityException} as cause.
 *
 * @author patrick
 */
public class CryptionInputStream extends InputStream {
    private final InputStream in;
    private final CryptionContext context;
    private final byte[] encryptedChunk;
    private final Cipher cipher;
    private byte[] chunk;
    private int position;
    private long counter;
    private int pending;
    private boolean finished;
    private boolean closed;
    private boolean failed;


    /**
     * Constructor for CryptionInputStream: decrypt with a private key.
     *
     * @param in the input stream of the encrypted data
     * @param cryption the asymmetric cryption
     * @param privateKey the RSA private key
     * @throws GeneralSecurityException in case of error, e.g. a wrong key or invalid data
     * @throws IOException in case of an I/O error
     */
    public CryptionInputStream(InputStream in, CryptionAsymmetric cryption, PrivateKey privateKey) throws GeneralSecurityException, IOException {
        this(in, checkCryption(cryption).readDecryptionContext(checkStream(in), privateKey));
    }


    /**
     * Constructor for CryptionInputStream: decrypt with an AES key.
     *
     * @param in the input stream of the encrypted data
     * @param cryption the symmetric cryption
     * @param key the AES key
     * @throws GeneralSecurityException in case of error, e.g. a wrong key or invalid data
     * @throws IOException in case of an I/O error
     */
    public CryptionInputStream(InputStream in, CryptionSymmetric cryption, SecretKey key) throws GeneralSecurityException, IOException {
        this(in, checkCryption(cryption).readDecryptionContext(checkStream(in), key));
    }


    /**
     * Constructor for CryptionInputStream: decrypt with a key derived from a passphrase.
     *
     * @param in the input stream of the encrypted data
     * @param cryption the symmetric cryption
     * @param passphrase the passphrase
     * @throws GeneralSecurityException in case of error, e.g. a wrong passphrase or invalid data
     * @throws IOException in case of an I/O error
     */
    public CryptionInputStream(InputStream in, CryptionSymmetric cryption, ISecuredSecretValue passphrase) throws GeneralSecurityException, IOException {
        this(in, checkCryption(cryption).readDecryptionContext(checkStream(in), passphrase));
    }


    /**
     * Constructor for CryptionInputStream: decrypt with a key derived from a passphrase.
     *
     * @param in the input stream of the encrypted data
     * @param cryption the symmetric cryption
     * @param passphrase the passphrase, it is not changed
     * @throws GeneralSecurityException in case of error, e.g. a wrong passphrase or invalid data
     * @throws IOException in case of an I/O error
     */
    public CryptionInputStream(InputStream in, CryptionSymmetric cryption, char[] passphrase) throws GeneralSecurityException, IOException {
        this(in, checkCryption(cryption).readDecryptionContext(checkStream(in), passphrase));
    }


    /**
     * Constructor for CryptionInputStream
     *
     * @param in the input stream of the encrypted data, the header is already read
     * @param context the context
     * @throws GeneralSecurityException in case of error
     */
    private CryptionInputStream(InputStream in, CryptionContext context) throws GeneralSecurityException {
        this.in = in;
        this.context = context;
        this.encryptedChunk = new byte[context.getChunkSize() + CryptionStreamSupport.TAG_SIZE];
        this.chunk = new byte[0];
        this.position = 0;
        this.counter = 0;
        this.pending = -1;
        this.finished = false;
        this.closed = false;
        this.failed = false;

        Cipher chunkCipher = null;
        try {
            chunkCipher = CryptionStreamSupport.createCipher(context);
        } catch (GeneralSecurityException | RuntimeException e) {
            context.destroy();
            throw e;
        }

        this.cipher = chunkCipher;
    }


    /**
     * @see java.io.InputStream#read()
     */
    @Override
    public int read() throws IOException {
        if (!fillChunk()) {
            return -1;
        }

        return chunk[position++] & 0xFF;
    }


    /**
     * @see java.io.InputStream#read(byte[], int, int)
     */
    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (b == null) {
            throw new NullPointerException();
        }

        if (off < 0 || len < 0 || len > b.length - off) {
            throw new IndexOutOfBoundsException();
        }

        if (len == 0) {
            return 0;
        }

        if (!fillChunk()) {
            return -1;
        }

        int length = Math.min(len, chunk.length - position);
        System.arraycopy(chunk, position, b, off, length);
        position += length;
        return length;
    }


    /**
     * @see java.io.InputStream#available()
     */
    @Override
    public int available() throws IOException {
        return chunk.length - position;
    }


    /**
     * @see java.io.InputStream#close()
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }

        closed = true;
        context.destroy();
        Arrays.fill(chunk, (byte) 0);
        Arrays.fill(encryptedChunk, (byte) 0);
        in.close();
    }


    /**
     * Make sure there is decrypted content to read.
     *
     * @return true if there is content, false at the end of the content
     * @throws IOException in case of error
     */
    private boolean fillChunk() throws IOException {
        if (closed) {
            throw new IOException("The stream is closed!");
        }

        if (failed) {
            throw new IOException("The stream is in a failed state after a previous error!", new GeneralSecurityException(CryptionStreamSupport.INVALID_DATA));
        }

        while (position >= chunk.length) {
            if (finished) {
                return false;
            }

            boolean success = false;
            try {
                readChunk();
                success = true;
            } finally {
                if (!success) {
                    failed = true;
                }
            }
        }

        return true;
    }


    /**
     * Read and decrypt the next chunk. A full chunk is the last one if the stream ends after it.
     *
     * @throws IOException in case of error
     */
    private void readChunk() throws IOException {
        int length = 0;
        if (pending >= 0) {
            encryptedChunk[length++] = (byte) pending;
            pending = -1;
        }

        length += CryptionStreamSupport.read(in, encryptedChunk, length, encryptedChunk.length - length);

        boolean last = true;
        if (length == encryptedChunk.length) {
            pending = in.read();
            last = pending < 0;
        }

        if (length < CryptionStreamSupport.TAG_SIZE) {
            throw new IOException(CryptionStreamSupport.INVALID_DATA, new GeneralSecurityException(CryptionStreamSupport.INVALID_DATA));
        }

        try {
            CryptionStreamSupport.initChunkCipher(cipher, Cipher.DECRYPT_MODE, context, counter, last);
            Arrays.fill(chunk, (byte) 0);
            chunk = cipher.doFinal(encryptedChunk, 0, length);
            position = 0;
            counter++;
            finished = last;
        } catch (GeneralSecurityException e) {
            throw new IOException("Decryption failed, wrong key or modified data: " + e.getMessage(), e);
        }
    }


    /**
     * Check the input stream.
     *
     * @param in the input stream
     * @return the input stream
     * @throws IOException if the input stream is null
     */
    private static InputStream checkStream(InputStream in) throws IOException {
        if (in == null) {
            throw new IOException("Invalid input stream!");
        }

        return in;
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
