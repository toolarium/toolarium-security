/*
 * ReadOnlyKeyStore.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;


/**
 * Read only view of a keystore: every read is delegated, every change is rejected with a {@link KeyStoreException}.
 * It is used for the shared default trust keystore, so a caller can not change the trust of the whole JVM by accident.
 *
 * @author patrick
 */
public final class ReadOnlyKeyStore extends KeyStore {
    private static final String READ_ONLY = "The keystore is read only!";


    /**
     * Constructor for ReadOnlyKeyStore: creates a read only view of the given keystore, which is ready to use.
     *
     * @param delegate the keystore to wrap, it must be initialized (loaded)
     * @throws IllegalArgumentException if the keystore is null
     * @throws IOException In case of an I/O error
     * @throws NoSuchAlgorithmException In case of a missing algorithm
     * @throws CertificateException In case of a certificate error
     */
    public ReadOnlyKeyStore(KeyStore delegate) throws IOException, NoSuchAlgorithmException, CertificateException {
        super(new ReadOnlyKeyStoreSpi(checkDelegate(delegate)), delegate.getProvider(), delegate.getType());
        load(null, null);
    }


    /**
     * Check the keystore to wrap.
     *
     * @param delegate the keystore to wrap
     * @return the keystore
     * @throws IllegalArgumentException if the keystore is null
     */
    private static KeyStore checkDelegate(KeyStore delegate) {
        if (delegate == null) {
            throw new IllegalArgumentException("Invalid keystore (null)!");
        }

        return delegate;
    }


    /**
     * The service provider interface of the read only keystore.
     */
    private static final class ReadOnlyKeyStoreSpi extends KeyStoreSpi {
        private final KeyStore delegate;


        /**
         * Constructor for ReadOnlyKeyStoreSpi
         *
         * @param delegate the keystore to wrap
         */
        ReadOnlyKeyStoreSpi(KeyStore delegate) {
            this.delegate = delegate;
        }


        /**
         * @see java.security.KeyStoreSpi#engineGetKey(java.lang.String, char[])
         */
        @Override
        public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
            try {
                return delegate.getKey(alias, password);
            } catch (KeyStoreException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }


        /**
         * @see java.security.KeyStoreSpi#engineGetCertificateChain(java.lang.String)
         */
        @Override
        public Certificate[] engineGetCertificateChain(String alias) {
            try {
                return delegate.getCertificateChain(alias);
            } catch (KeyStoreException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }


        /**
         * @see java.security.KeyStoreSpi#engineGetCertificate(java.lang.String)
         */
        @Override
        public Certificate engineGetCertificate(String alias) {
            try {
                return delegate.getCertificate(alias);
            } catch (KeyStoreException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }


        /**
         * @see java.security.KeyStoreSpi#engineGetCreationDate(java.lang.String)
         */
        @Override
        public Date engineGetCreationDate(String alias) {
            try {
                return delegate.getCreationDate(alias);
            } catch (KeyStoreException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }


        /**
         * @see java.security.KeyStoreSpi#engineSetKeyEntry(java.lang.String, java.security.Key, char[], java.security.cert.Certificate[])
         */
        @Override
        public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
            throw new KeyStoreException(READ_ONLY);
        }


        /**
         * @see java.security.KeyStoreSpi#engineSetKeyEntry(java.lang.String, byte[], java.security.cert.Certificate[])
         */
        @Override
        public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
            throw new KeyStoreException(READ_ONLY);
        }


        /**
         * @see java.security.KeyStoreSpi#engineSetCertificateEntry(java.lang.String, java.security.cert.Certificate)
         */
        @Override
        public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
            throw new KeyStoreException(READ_ONLY);
        }


        /**
         * @see java.security.KeyStoreSpi#engineDeleteEntry(java.lang.String)
         */
        @Override
        public void engineDeleteEntry(String alias) throws KeyStoreException {
            throw new KeyStoreException(READ_ONLY);
        }


        /**
         * @see java.security.KeyStoreSpi#engineAliases()
         */
        @Override
        public Enumeration<String> engineAliases() {
            try {
                return delegate.aliases();
            } catch (KeyStoreException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }


        /**
         * @see java.security.KeyStoreSpi#engineContainsAlias(java.lang.String)
         */
        @Override
        public boolean engineContainsAlias(String alias) {
            try {
                return delegate.containsAlias(alias);
            } catch (KeyStoreException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }


        /**
         * @see java.security.KeyStoreSpi#engineSize()
         */
        @Override
        public int engineSize() {
            try {
                return delegate.size();
            } catch (KeyStoreException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }


        /**
         * @see java.security.KeyStoreSpi#engineIsKeyEntry(java.lang.String)
         */
        @Override
        public boolean engineIsKeyEntry(String alias) {
            try {
                return delegate.isKeyEntry(alias);
            } catch (KeyStoreException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }


        /**
         * @see java.security.KeyStoreSpi#engineIsCertificateEntry(java.lang.String)
         */
        @Override
        public boolean engineIsCertificateEntry(String alias) {
            try {
                return delegate.isCertificateEntry(alias);
            } catch (KeyStoreException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }


        /**
         * @see java.security.KeyStoreSpi#engineGetCertificateAlias(java.security.cert.Certificate)
         */
        @Override
        public String engineGetCertificateAlias(Certificate cert) {
            try {
                return delegate.getCertificateAlias(cert);
            } catch (KeyStoreException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }


        /**
         * @see java.security.KeyStoreSpi#engineStore(java.io.OutputStream, char[])
         */
        @Override
        public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
            try {
                delegate.store(stream, password);
            } catch (KeyStoreException e) {
                throw new IOException(e.getMessage(), e);
            }
        }


        /**
         * Only the initialization without data is allowed: the content of a read only keystore can not be replaced.
         *
         * @see java.security.KeyStoreSpi#engineLoad(java.io.InputStream, char[])
         */
        @Override
        public void engineLoad(InputStream stream, char[] password) throws IOException {
            if (stream != null) {
                throw new IOException(READ_ONLY);
            }
        }
    }
}
