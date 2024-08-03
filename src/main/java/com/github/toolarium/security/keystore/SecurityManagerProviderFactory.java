/*
 * SecurityKeyAccessFactory.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore;

import com.github.toolarium.common.security.ISecuredValue;
import com.github.toolarium.common.security.SecuredValue;
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
    private static final Logger LOG = LoggerFactory.getLogger(SecurityManagerProviderFactory.class);
    
    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
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
     * @return the security manager provider
     */
    public ISecurityManagerProvider getSecurityManagerProvider() {
        return getSecurityManagerProvider("toolarium", "changit"); 
    }
    
    
    /**
     * Get the security manager provider with self-signed certificate and added to the trust store. 
     * 
     * @param certificateStoreAlias the certificate store alias
     * @param keyStorePassword the key store password
     * @return the security manager provider
     */
    public ISecurityManagerProvider getSecurityManagerProvider(String certificateStoreAlias, String keyStorePassword) {
        return getSecurityManagerProvider(null, null, certificateStoreAlias, keyStorePassword);
    }

    
    /**
     * Get the security manager provider with self-signed certificate and added to the trust store. 
     * 
     * @param keyStoreFile the key store file or null. In case of null, it will be created only in memory; otherwise the created key store will be saved.
     * @param provider the provider or null
     * @param keyStorePassword the key store password
     * @param certificateStoreAlias the certificate store alias
     * @return the security manager provider
     */
    public ISecurityManagerProvider getSecurityManagerProvider(String keyStoreFile, String provider, String keyStorePassword, String certificateStoreAlias) {
        try {
            // create key store
            CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(certificateStoreAlias);
            final KeyStore keyStore = certificateStore.toKeyStore(certificateStoreAlias, keyStorePassword);

            if (keyStoreFile != null) {
                KeyStoreUtil.getInstance().writePKCS12KeyStore(keyStoreFile, provider, certificateStoreAlias, certificateStore.getKeyPair().getPrivate(), certificateStore.getCertificates(), new SecuredValue<String>(keyStorePassword));
            }

            return getSecurityManagerProvider(keyStore, keyStorePassword, certificateStoreAlias);
        } catch (IOException | GeneralSecurityException e) {
            LOG.warn("Could not create certificate: " + e.getMessage(), e);
            return null;
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
     */
    public ISecurityManagerProvider getSecurityManagerProvider(String keyStoreFile, String type, String provider, String keyStorePassword, String certificateStoreAlias) {
        try {
            final KeyStore keyStore = KeyStoreUtil.getInstance().readKeyStore(keyStoreFile, type, provider, new SecuredValue<String>(keyStorePassword));
            return getSecurityManagerProvider(keyStore, keyStorePassword, certificateStoreAlias);
        } catch (IOException | GeneralSecurityException e) {
            LOG.warn("Could not create certificate: " + e.getMessage(), e);
            return null;
        }
    }

    
    /**
     * Get the key store file and added the certificate to the trust store. 
     * 
     * @param keyStore the key store
     * @param keyStorePassword the key store password
     * @param certificateStoreAlias the certificate store alias
     * @return the security manager provider
     */
    public ISecurityManagerProvider getSecurityManagerProvider(KeyStore keyStore, String keyStorePassword, String certificateStoreAlias) {
        try {
            // get certificate
            X509Certificate selfSignedCertificate = (X509Certificate)keyStore.getCertificate(certificateStoreAlias);

            // get trust manager and add the self-signed certificate 
            final KeyStore trustKeyStore = KeyStoreUtil.getInstance().addCertificateToTrustKeystore(certificateStoreAlias, selfSignedCertificate);
            return new SecurityManagerProviderImpl(trustKeyStore, keyStore, new SecuredValue<String>(keyStorePassword, "..."));
        } catch (IOException | GeneralSecurityException e) {
            LOG.warn("Could not create certificate: " + e.getMessage(), e);
            return null;
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
    public ISecurityManagerProvider getSecurityManagerProvider(KeyStore trustKeyStore, KeyStore keyStore, ISecuredValue<String> keyStorePassword) {
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
    public ISecurityManagerProvider getSecurityManagerProvider(File trustKeyStoreFile, File keyStoreFile, ISecuredValue<String> keyStorePassword)
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
    public ISecurityManagerProvider getSecurityManagerProvider(File trustKeyStoreFile, File keyStoreFile, ISecuredValue<String> keyStorePassword, String keyStoreType)
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
            trustKeyStore = KeyStoreUtil.getInstance().readKeyStore(trustKeyStoreConfiguration.getKeyStoreFile().getName(), 
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
