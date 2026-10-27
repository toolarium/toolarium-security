/*
 * CryptionContext.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.cryption;

import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;


/**
 * The context of one encryption or decryption: the header of the encrypted data, the AES key of the content, the
 * chunk size and the provider. The key is cleared with {@link #destroy()}; afterwards the key can not be used anymore.
 *
 * @author patrick
 */
final class CryptionContext implements Destroyable {
    private static final String AES = "AES";
    private static final String DESTROYED_MESSAGE = "The cryption context is destroyed!";
    private final byte[] header;
    private final byte[] key;
    private final int chunkSize;
    private final String provider;
    private volatile SecretKeySpec keySpec;
    private volatile boolean destroyed;


    /**
     * Constructor for CryptionContext
     *
     * @param header the header, it ends with the nonce prefix
     * @param key the AES key of the content
     * @param chunkSize the chunk size
     * @param provider the provider or null for the default provider
     */
    CryptionContext(byte[] header, byte[] key, int chunkSize, String provider) {
        this.header = header;
        this.key = key;
        this.chunkSize = chunkSize;
        this.provider = provider;
        this.keySpec = new SecretKeySpec(key, AES);
        this.destroyed = false;
    }


    /**
     * Get the header of the encrypted data.
     *
     * @return the header
     */
    byte[] getHeader() {
        return header;
    }


    /**
     * Get the AES key of the content.
     *
     * @return the key
     * @throws IllegalStateException if the context is destroyed
     */
    byte[] getKey() {
        if (destroyed) {
            throw new IllegalStateException(DESTROYED_MESSAGE);
        }

        return key;
    }


    /**
     * Get the AES key of the content as key specification. It is created once per context and used for every chunk.
     *
     * @return the key specification
     * @throws IllegalStateException if the context is destroyed
     */
    SecretKeySpec getKeySpec() {
        SecretKeySpec result = keySpec;
        if (destroyed || result == null) {
            throw new IllegalStateException(DESTROYED_MESSAGE);
        }

        return result;
    }


    /**
     * Get the chunk size.
     *
     * @return the chunk size
     */
    int getChunkSize() {
        return chunkSize;
    }


    /**
     * Get the provider.
     *
     * @return the provider or null for the default provider
     */
    String getProvider() {
        return provider;
    }


    /**
     * Clear the key.
     *
     * @see javax.security.auth.Destroyable#destroy()
     */
    @Override
    public synchronized void destroy() {
        Arrays.fill(key, (byte) 0);
        keySpec = null;
        destroyed = true;
    }


    /**
     * @see javax.security.auth.Destroyable#isDestroyed()
     */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}
