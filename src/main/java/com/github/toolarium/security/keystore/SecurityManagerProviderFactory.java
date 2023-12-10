/*
 * SecurityKeyAccessFactory.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore;

import com.github.toolarium.common.security.ISecuredValue;
import com.github.toolarium.common.security.SecuredValue;
import com.github.toolarium.security.certificate.X509CertificateGenerator;
import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.certificate.util.PKIUtil;
import com.github.toolarium.security.keystore.dto.IKeyStoreConfiguration;
import com.github.toolarium.security.keystore.dto.KeyStoreConfiguration;
import com.github.toolarium.security.keystore.impl.SecurityManagerProviderImpl;
import com.github.toolarium.security.keystore.util.KeyStoreUtil;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Defines the security manager provider factory
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
     * Get the security manager provider with self signed certificate and added to the trust store. 
     *
     * @return the security manager provider
     */
    public ISecurityManagerProvider getSecurityManagerProvider() {
        return getSecurityManagerProvider("toolarium", "changit"); 
    }
    
    
    /**
     * Get the security manager provider with self signed certificate and added to the trust store. 
     * 
     * @param certificateStoreAlias the certificate store alias
     * @param keyStorePassword the keystore password
     * @return the security manager provider
     */
    public ISecurityManagerProvider getSecurityManagerProvider(String certificateStoreAlias, String keyStorePassword) {
        try {
            CertificateStore certificateStore = X509CertificateGenerator.getInstance().createCreateCertificate(certificateStoreAlias);
            final KeyStore keyManagerStore = certificateStore.toKeyStore(certificateStoreAlias, keyStorePassword);
            final KeyStore trustManagerKeyStore = KeyStoreUtil.getInstance().createKeyStore(null);
            
            X509TrustManager defaultTm = KeyStoreUtil.getInstance().getDefaultX509TrustManager();
            X509Certificate[] trustedIssuers = defaultTm.getAcceptedIssuers();
            if (trustedIssuers != null) {
                int i = 1;
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Init new default trust stire with default trusted issuers: " + trustedIssuers.length);
                }

                for (X509Certificate trustedIssuer : trustedIssuers) {
                    // add the key manager store in the trust store
                    trustManagerKeyStore.setCertificateEntry("cert" + i++, trustedIssuer);
                    
                    //if (LOG.isDebugEnabled()) {
                    //    PKIUtil.getInstance().processCertificate(LOG::debug, "Add certificate to trust store:", trustedIssuers);
                    //}
                }
            }

            // add the key manager store in the trust store
            X509Certificate selfSignedCertificate = (X509Certificate)keyManagerStore.getCertificate(certificateStoreAlias);
            trustManagerKeyStore.setCertificateEntry(certificateStoreAlias, selfSignedCertificate);
            if (LOG.isDebugEnabled()) {
                PKIUtil.getInstance().processCertificate(LOG::debug, "Add self-signed certificate to trust store:", selfSignedCertificate);
            }
            
            
            return new SecurityManagerProviderImpl(trustManagerKeyStore, keyManagerStore, new SecuredValue<String>(keyStorePassword, "..."));
        } catch (IOException | GeneralSecurityException e) {
            LOG.warn("Could not create certificate: " + e.getMessage(), e);
            return null;
        }
    }

    
    /**
     * Get the security manager provider
     *
     * @param trustKeyStore the trust key store
     * @param keyManagerKeyStore the key manager store
     * @param keyManagerStorePassword the key manager store password
     * @return the security manager provider
     */
    public ISecurityManagerProvider getSecurityManagerProvider(KeyStore trustKeyStore, KeyStore keyManagerKeyStore, ISecuredValue<String> keyManagerStorePassword) {
        return new SecurityManagerProviderImpl(trustKeyStore, keyManagerKeyStore, keyManagerStorePassword);
    }

    
    /**
     * Get the security manager provider
     *
     * @param trustKeyStoreFile the trust key store file or null to use the default
     * @param keyManagerKeyStoreFile the key manager store file
     * @param keyManagerStorePassword the key manager store password
     * @return the security manager provider
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    public ISecurityManagerProvider getSecurityManagerProvider(File trustKeyStoreFile, File keyManagerKeyStoreFile, ISecuredValue<String> keyManagerStorePassword)
            throws GeneralSecurityException, IOException {
        return getSecurityManagerProvider(trustKeyStoreFile, keyManagerKeyStoreFile, keyManagerStorePassword, null); 
    }

    
    /**
     * Get the security manager provider
     *
     * @param trustKeyStoreFile the trust key store file or null to use the default
     * @param keyManagerKeyStoreFile the key manager store file
     * @param keyManagerStorePassword the key manager store password
     * @param keyStoreType the key store type or null
     * @return the security manager provider
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    public ISecurityManagerProvider getSecurityManagerProvider(File trustKeyStoreFile, File keyManagerKeyStoreFile, ISecuredValue<String> keyManagerStorePassword, String keyStoreType)
            throws GeneralSecurityException, IOException {
        return getSecurityManagerProvider(new KeyStoreConfiguration(trustKeyStoreFile, null, keyStoreType, null, null), new KeyStoreConfiguration(keyManagerKeyStoreFile, null, keyStoreType, null, keyManagerStorePassword)); 
    }


    /**
     * Get the security manager provider
     *
     * @param trustKeyStoreConfiguration the trust key store configuration or null to use the default
     * @param keyManagerKeyStoreConfiguration the key manager store file
     * @return the security manager provider
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    public ISecurityManagerProvider getSecurityManagerProvider(IKeyStoreConfiguration trustKeyStoreConfiguration, IKeyStoreConfiguration keyManagerKeyStoreConfiguration)
            throws GeneralSecurityException, IOException {
        KeyStore trustKeyStore = null; // default -> JAVA_HOME/jre/lib/security/cacerts
        if (trustKeyStoreConfiguration != null) {
            trustKeyStore = KeyStoreUtil.getInstance().readKeyStore(trustKeyStoreConfiguration.getKeyStoreFile().getName(), 
                                                                    trustKeyStoreConfiguration.getKeyStoreType(), 
                                                                    trustKeyStoreConfiguration.getKeyStoreProvider(),
                                                                    trustKeyStoreConfiguration.getKeyStorePassword());  
        }
            
        KeyStore keyManagerKeyStore = KeyStoreUtil.getInstance().readKeyStore(keyManagerKeyStoreConfiguration.getKeyStoreFile().getPath(),
                                                                              keyManagerKeyStoreConfiguration.getKeyStoreType(),
                                                                              keyManagerKeyStoreConfiguration.getKeyStoreProvider(),
                                                                              keyManagerKeyStoreConfiguration.getKeyStorePassword());

        return new SecurityManagerProviderImpl(trustKeyStore, keyManagerKeyStore, keyManagerKeyStoreConfiguration.getKeyStorePassword());
    }
}
