/*
 * SecurityKeyAccessFactory.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore;

import com.github.toolarium.common.security.ISecuredSecretValue;
import com.github.toolarium.common.security.SecuredValueFactory;
import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.keystore.dto.IKeyStoreConfiguration;
import com.github.toolarium.security.keystore.dto.KeyStoreConfiguration;
import com.github.toolarium.security.keystore.impl.SecurityManagerProviderImpl;
import com.github.toolarium.security.keystore.util.KeyStoreUtil;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Defines the security manager provider factory. The {@link ISecurityManagerProvider} contains the {@link KeyManager} and the {@link TrustManager}.
 *  
 * @author patrick
 */
public final class SecurityManagerProviderFactory {
    /** Default certificate store alias used by the no-arg convenience method. */
    public static final String DEFAULT_ALIAS = "toolarium";

    /** Default keystore password used by the no-arg convenience method (development/testing only). */
    public static final String DEFAULT_PASSWORD = "changit";

    private static final Logger LOG = LoggerFactory.getLogger(SecurityManagerProviderFactory.class);
    
    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static final class HOLDER {
        static final SecurityManagerProviderFactory INSTANCE = new SecurityManagerProviderFactory();
    }
    
    
    /**
     * Constructor
     */
    private SecurityManagerProviderFactory() {
        // NOP
    }
    
    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static SecurityManagerProviderFactory getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Get the security manager provider with self-signed certificate and added to the trust store.
     *
     * <p><strong>WARNING: FOR DEVELOPMENT / TESTING ONLY.</strong>
     * This convenience overload uses the hardcoded alias {@code "toolarium"} and the well-known
     * default password {@code "changit"}. Do NOT use this in production — supply explicit credentials
     * via {@link #getSecurityManagerProvider(String, char[])} or another overload instead.</p>
     *
     * @return the security manager provider
     * @throws GeneralSecurityException in case of error
     */
    public ISecurityManagerProvider getSecurityManagerProvider() throws GeneralSecurityException {
        return getSecurityManagerProvider(DEFAULT_ALIAS, DEFAULT_PASSWORD.toCharArray());
    }


    /**
     * Get the security manager provider with self-signed certificate and added to the trust store.
     *
     * @param certificateStoreAlias the certificate store alias
     * @param keyStorePassword the key store password
     * @return the security manager provider
     * @throws GeneralSecurityException in case of error
     */
    public ISecurityManagerProvider getSecurityManagerProvider(String certificateStoreAlias, char[] keyStorePassword)
            throws GeneralSecurityException {
        return getSecurityManagerProvider(null, null, keyStorePassword, certificateStoreAlias);
    }

    
    /**
     * Get the security manager provider with self-signed certificate and added to the trust store. 
     * 
     * @param keyStoreFile the key store file or null. In case of null, it will be created only in memory; otherwise the created key store will be saved.
     * @param provider the provider or null
     * @param keyStorePassword the key store password
     * @param certificateStoreAlias the certificate store alias
     * @return the security manager provider
     * @throws GeneralSecurityException in case of error
     */
    public ISecurityManagerProvider getSecurityManagerProvider(String keyStoreFile, String provider, char[] keyStorePassword, String certificateStoreAlias)
            throws GeneralSecurityException {
        // wrap immediately so the char[] is zeroed and we use the ISecuredSecretValue for all subsequent operations
        return getSecurityManagerProvider(keyStoreFile, provider, SecuredValueFactory.getInstance().createSecret(keyStorePassword, "..."), certificateStoreAlias);
    }


    /**
     * Get the security manager provider with self-signed certificate and added to the trust store.
     *
     * @param keyStoreFile the key store file or null
     * @param provider the provider or null
     * @param keyStorePassword the key store password
     * @param certificateStoreAlias the certificate store alias
     * @return the security manager provider
     * @throws GeneralSecurityException in case of error
     */
    private ISecurityManagerProvider getSecurityManagerProvider(String keyStoreFile, String provider, ISecuredSecretValue keyStorePassword, String certificateStoreAlias)
            throws GeneralSecurityException {
        try {
            // create key store
            CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(certificateStoreAlias);
            final KeyStore keyStore = certificateStore.toKeyStore(certificateStoreAlias, keyStorePassword);

            if (keyStoreFile != null) {
                KeyStoreUtil.getInstance().writePKCS12KeyStore(keyStoreFile, provider, certificateStoreAlias, certificateStore.getKeyPair().getPrivate(), certificateStore.getCertificates(), keyStorePassword);
            }

            return getSecurityManagerProvider(keyStore, keyStorePassword, certificateStoreAlias);
        } catch (IOException e) {
            throw new GeneralSecurityException("Could not create certificate: " + e.getMessage(), e);
        }
    }

    
    /**
     * Get the key store file and added the certificate to the trust store. 
     * 
     * @param keyStoreFile the key store file
     * @param type the key store type
     * @param provider the provider or null
     * @param keyStorePassword the key store password
     * @param certificateStoreAlias the certificate store alias
     * @return the security manager provider
     * @throws GeneralSecurityException in case of error
     */
    public ISecurityManagerProvider getSecurityManagerProvider(String keyStoreFile, String type, String provider, char[] keyStorePassword, String certificateStoreAlias)
            throws GeneralSecurityException {
        // wrap immediately so the char[] is zeroed and the ISecuredSecretValue is used for all subsequent operations
        ISecuredSecretValue pwSecret = SecuredValueFactory.getInstance().createSecret(keyStorePassword, "...");
        try {
            final KeyStore keyStore = KeyStoreUtil.getInstance().readKeyStore(keyStoreFile, type, provider, pwSecret);
            return getSecurityManagerProvider(keyStore, pwSecret, certificateStoreAlias);
        } catch (IOException e) {
            throw new GeneralSecurityException("Could not read keystore: " + e.getMessage(), e);
        }
    }

    
    /**
     * Get the key store file and added the certificate to the trust store. 
     * 
     * @param keyStore the key store
     * @param keyStorePassword the key store password
     * @param certificateStoreAlias the certificate store alias
     * @return the security manager provider
     * @throws GeneralSecurityException in case of error
     */
    public ISecurityManagerProvider getSecurityManagerProvider(KeyStore keyStore, char[] keyStorePassword, String certificateStoreAlias)
            throws GeneralSecurityException {
        return getSecurityManagerProvider(keyStore, SecuredValueFactory.getInstance().createSecret(keyStorePassword, "..."), certificateStoreAlias);
    }


    /**
     * Get the key store file and added the certificate to the trust store.
     *
     * @param keyStore the key store
     * @param keyStorePassword the key store password
     * @param certificateStoreAlias the certificate store alias
     * @return the security manager provider
     * @throws GeneralSecurityException in case of error
     */
    private ISecurityManagerProvider getSecurityManagerProvider(KeyStore keyStore, ISecuredSecretValue keyStorePassword, String certificateStoreAlias)
            throws GeneralSecurityException {
        try {
            // get certificate
            X509Certificate selfSignedCertificate = (X509Certificate)keyStore.getCertificate(certificateStoreAlias);

            // get trust manager and add the self-signed certificate
            final KeyStore trustKeyStore = KeyStoreUtil.getInstance().addCertificateToTrustKeystore(certificateStoreAlias, selfSignedCertificate);
            return new SecurityManagerProviderImpl(trustKeyStore, keyStore, keyStorePassword);
        } catch (IOException e) {
            throw new GeneralSecurityException("Could not create trust keystore: " + e.getMessage(), e);
        }
    }

    
    /**
     * Get the security manager provider
     *
     * @param trustKeyStore the trust key store
     * @param keyStore the key store
     * @param keyStorePassword the key store password
     * @return the security manager provider
     */
    public ISecurityManagerProvider getSecurityManagerProvider(KeyStore trustKeyStore, KeyStore keyStore, ISecuredSecretValue keyStorePassword) {
        return new SecurityManagerProviderImpl(trustKeyStore, keyStore, keyStorePassword);
    }

    
    /**
     * Get the security manager provider
     *
     * @param trustKeyStoreFile the trust key store file or null to use the default
     * @param keyStoreFile the key store file
     * @param keyStorePassword the key store password
     * @return the security manager provider
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    public ISecurityManagerProvider getSecurityManagerProvider(File trustKeyStoreFile, File keyStoreFile, ISecuredSecretValue keyStorePassword)
            throws GeneralSecurityException, IOException {
        return getSecurityManagerProvider(trustKeyStoreFile, keyStoreFile, keyStorePassword, null); 
    }

    
    /**
     * Get the security manager provider
     *
     * @param trustKeyStoreFile the trust key store file or null to use the default
     * @param keyStoreFile the key store file
     * @param keyStorePassword the key store password
     * @param keyStoreType the key store type or null
     * @return the security manager provider
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    public ISecurityManagerProvider getSecurityManagerProvider(File trustKeyStoreFile, File keyStoreFile, ISecuredSecretValue keyStorePassword, String keyStoreType)
            throws GeneralSecurityException, IOException {
        return getSecurityManagerProvider(new KeyStoreConfiguration(trustKeyStoreFile, null, keyStoreType, null, null), new KeyStoreConfiguration(keyStoreFile, null, keyStoreType, null, keyStorePassword)); 
    }


    /**
     * Get the security manager provider
     *
     * @param trustKeyStoreConfiguration the trust key store configuration or null to use the default
     * @param keyStoreConfiguration the key store file
     * @return the security manager provider
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    public ISecurityManagerProvider getSecurityManagerProvider(IKeyStoreConfiguration trustKeyStoreConfiguration, IKeyStoreConfiguration keyStoreConfiguration)
            throws GeneralSecurityException, IOException {
        KeyStore trustKeyStore = null; // default -> JAVA_HOME/jre/lib/security/cacerts
        if (trustKeyStoreConfiguration != null) {
            trustKeyStore = KeyStoreUtil.getInstance().readKeyStore(trustKeyStoreConfiguration.getKeyStoreFile().getPath(),
                                                                    trustKeyStoreConfiguration.getKeyStoreType(), 
                                                                    trustKeyStoreConfiguration.getKeyStoreProvider(),
                                                                    trustKeyStoreConfiguration.getKeyStorePassword());  
        }
            
        KeyStore keyStore = KeyStoreUtil.getInstance().readKeyStore(keyStoreConfiguration.getKeyStoreFile().getPath(),
                                                                    keyStoreConfiguration.getKeyStoreType(),
                                                                    keyStoreConfiguration.getKeyStoreProvider(),
                                                                    keyStoreConfiguration.getKeyStorePassword());

        return new SecurityManagerProviderImpl(trustKeyStore, keyStore, keyStoreConfiguration.getKeyStorePassword());
    }
}
