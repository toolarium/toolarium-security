/*
 * SecurityManagerImpl.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.impl;

import com.github.toolarium.common.security.ISecuredSecretValue;
import com.github.toolarium.security.keystore.ISecurityManagerProvider;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Implements {@link ISecurityManagerProvider}.
 * 
 * @author patrick
 */
public class SecurityManagerProviderImpl implements ISecurityManagerProvider {
    private static final Logger LOG = LoggerFactory.getLogger(SecurityManagerProviderImpl.class);
    private final transient KeyStore trustManagerStore;
    private final transient KeyStore keyManagerStore;
    private final transient ISecuredSecretValue keyManagerStorePassword;
    
    
    /**
     * Constructor for SecurityManagerImpl
     *
     * @param trustManagerStore the trust manager store
     * @param keyManagerStore the key manager store
     * @param keyManagerStorePassword the key manager store password
     * @throws IllegalArgumentException In case of an invalid key manager store or password
     */
    public SecurityManagerProviderImpl(KeyStore trustManagerStore, KeyStore keyManagerStore, ISecuredSecretValue keyManagerStorePassword) {
        this.trustManagerStore = trustManagerStore;
        this.keyManagerStore = keyManagerStore;
        this.keyManagerStorePassword = keyManagerStorePassword;
    }


    /**
     * @see com.github.toolarium.security.keystore.ISecurityManagerProvider#getTrustManagers()
     */
    @Override
    public TrustManager[] getTrustManagers() throws GeneralSecurityException {
        return createTrustManagers(trustManagerStore);
    }


    /**
     * @see com.github.toolarium.security.keystore.ISecurityManagerProvider#getKeyManagers()
     */
    @Override
    public KeyManager[] getKeyManagers() throws GeneralSecurityException {
        return createKeyManager(keyManagerStore, keyManagerStorePassword);
    }

    
    /**
     * Create a {@link KeyManager} for the given key store
     * 
     * @param keyStore The key store
     * @param storePassword the store password
     * @return The key managers in the given key store
     * @throws GeneralSecurityException if the key store could not be loaded
     */
    protected KeyManager[] createKeyManager(final KeyStore keyStore, final ISecuredSecretValue storePassword) throws GeneralSecurityException {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            if (keyStore != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Initialize key manager factory by [" + keyStore + "] of type " + KeyManagerFactory.getDefaultAlgorithm() + "...");
                }
                withSecret(storePassword, chars -> keyManagerFactory.init(keyStore, chars));
            }
            
            return keyManagerFactory.getKeyManagers();
        } catch (GeneralSecurityException ex) {
            throw new GeneralSecurityException("Unable to initialise KeyManager:" + ex.getMessage(), ex);
        }
    }

    
    @FunctionalInterface
    private interface SecretAction {
        /**
         * Run the action with the given password chars.
         *
         * @param pw the password chars, or {@code null} if no secret is set
         * @throws GeneralSecurityException in case of error
         */
        void run(char[] pw) throws GeneralSecurityException;
    }


    /**
     * Execute a secret action using the chars from the given secret value.
     * If the secret is null or has no value, the action is invoked with a null char array.
     *
     * @param secret the secret value
     * @param action the action to run
     * @throws GeneralSecurityException in case of error
     */
    private static void withSecret(ISecuredSecretValue secret, SecretAction action) throws GeneralSecurityException {
        if (secret == null || secret.getValue() == null) {
            action.run(null);
        } else {
            try {
                secret.getValue().useChars(chars -> {
                    try {
                        action.run(chars);
                    } catch (GeneralSecurityException e) {
                        throw new RuntimeException(e);
                    }
                    return null;
                });
            } catch (RuntimeException e) {
                Throwable c = e.getCause();
                if (c instanceof GeneralSecurityException) {
                    throw (GeneralSecurityException) c;
                }
                throw e;
            }
        }
    }


    /**
     * Create a {@link TrustManager} for the given key store.
     * 
     * @param keyStore The key store
     * @return The trust manager
     * @throws GeneralSecurityException if the creation failed
     */
    protected TrustManager[] createTrustManagers(final KeyStore keyStore) throws GeneralSecurityException {
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Initialize trust manager factory by [" + keyStore + "] of type " + KeyManagerFactory.getDefaultAlgorithm() + "...");
            }
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            
            //ToolariumTrustManager toolariumTrustManager = new ToolariumTrustManager();
            //toolariumTrustManager.addTrustedCertificate((X509Certificate)keyStore.getCertificate("toolarium"));
            //return new TrustManager[] {toolariumTrustManager};  // TODO:
            return trustManagerFactory.getTrustManagers();
        } catch (GeneralSecurityException ex) {
            throw new GeneralSecurityException("Unable to initialise TrustManager: " + ex.getMessage(), ex);
        }
    }
}
