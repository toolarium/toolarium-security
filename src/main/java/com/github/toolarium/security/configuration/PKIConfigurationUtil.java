/*
 * PKIConfigurationUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.configuration;

import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.keystore.util.KeyStoreUtil;
import com.github.toolarium.security.pki.KeyConverterFactory;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * PKI configuration util. It supports cases where you have a simple string of certificates,
 * private key, public key and you need the converted object.
 * 
 * @author patrick
 */
public final class PKIConfigurationUtil {
    private static final Logger LOG = LoggerFactory.getLogger(PKIConfigurationUtil.class);
    private static final String START_CERTIFICATE = "-----BEGIN";
    private static final String END_CERTIFICATE_KEY = "CERTIFICATE-----";
    private static final String END_PRIVATE_KEY = "PRIVATE KEY-----";
    private static final String END_PUBLIC_KEY = "PUBLIC KEY-----";
     
    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     */
    private static final class HOLDER {
        static final PKIConfigurationUtil INSTANCE = new PKIConfigurationUtil();
    }

    
    /**
     * Constructor
     */
    private PKIConfigurationUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static PKIConfigurationUtil getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Add a certificate into a key-store
     * 
     * @param alias the alias. If there are multiple certificates the index number will be added to the alias, e.g. alias0, alias1... 
     * @param certificate the certificate, a PKCS#7 (with base64 encoded) X509 certificates, which are each bounded at the 
     *        beginning by <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     * @return the key-store with added certificate
     * @throws GeneralSecurityException In case of general security exception
     */
    public KeyStore getKeyStore(String alias, String certificate) throws GeneralSecurityException {
        if (certificate == null || certificate.isBlank()) {
            throw new GeneralSecurityException("Invalid certificate!");
        }

        final KeyStore keyStore;
        try {
            keyStore = KeyStoreUtil.getInstance().createKeyStore(null);
        } catch (IOException e) {
            throw new GeneralSecurityException(e.getMessage(), e);
        }
        
        final X509Certificate[] certificateChain = getCertificate(certificate);

        // get certificate
        if (keyStore != null && certificateChain != null) {
            List<X509Certificate> list = new ArrayList<X509Certificate>();
            list.addAll(CertificateUtilFactory.getInstance().getFilter().filterValid(Arrays.asList(certificateChain)));
            list.addAll(CertificateUtilFactory.getInstance().getFilter().filterNotYedValid(Arrays.asList(certificateChain)));
        
            for (int i = 0; i < list.size(); i++) {
                // add the key manager store in the store
                keyStore.setCertificateEntry(alias + i, list.get(i));
                if (LOG.isDebugEnabled()) {
                    PKIUtil.getInstance().processCertificate(LOG::debug, "Add certificate to key store:", list.get(i));
                }
            }
        }
        
        return keyStore;
    }


    /**
     * Add a certificate into the default trust store
     *
     * @param alias the alias. If there are multiple certificates the index number will be added to the alias, e.g. alias0, alias1... 
     * @param certificate the certificate, a PKCS#7 (with base64 encoded) X509 certificates, which are each bounded at the 
     *        beginning by <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     * @return the trust key-store with added certificate
     * @throws GeneralSecurityException In case of general security exception
     */
    public KeyStore getTrustKeyStore(String alias, String certificate) throws GeneralSecurityException {
        if (certificate == null || certificate.isBlank()) {
            throw new GeneralSecurityException("Invalid trust certificate!");
        }
        
        // get certificate
        X509Certificate[] certificateChain = getCertificate(certificate);
        
        // get trust key-store with added certificate chain
        try {
            return KeyStoreUtil.getInstance().addCertificateToTrustKeystore(alias, certificateChain);
        } catch (IOException e) {
            throw new GeneralSecurityException(e.getMessage(), e);
        }
    }

    
    /**
     * Add a certificate into the default trust store and return the trust manager.
     *
     * @param alias the alias. If there are multiple certificates the index number will be added to the alias, e.g. alias0, alias1... 
     * @param certificate the certificate, a PKCS#7 (with base64 encoded) X509 certificates, which are each bounded at the 
     *        beginning by <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     * @return the trust key-store with added certificate
     * @throws GeneralSecurityException In case of general security exception
     */
    public TrustManager[] getTrustManagers(String alias, String certificate) throws GeneralSecurityException {
        if (certificate == null || certificate.isBlank()) {
            throw new GeneralSecurityException("Invalid trust certificate!");
        }
        
        // get certificate as key-store
        final KeyStore trustKeyStore = getTrustKeyStore(alias, certificate);
        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustKeyStore);
        return trustManagerFactory.getTrustManagers();
    }

    
    /**
     * Get the private key from a PKCS#8 formated private key, which is bounded at the beginning by
     * <code>-----BEGIN ... PRIVATE KEY-----</code>, and bounded at the end by <code>-----END ... PRIVATE KEY-----</code>.
     *
     * @param inputPrivateKeyString the PKCS#8 formated private key
     * @return the private key
     * @throws GeneralSecurityException In case of general security exception
     */
    public PrivateKey getPrivateKey(String inputPrivateKeyString) throws GeneralSecurityException {
        return getPrivateKey(inputPrivateKeyString, null);
    }
    
    
    /**
     * Get the private key from a PKCS#8 formated private key, which is bounded at the beginning by
     * <code>-----BEGIN ... PRIVATE KEY-----</code>, and bounded at the end by <code>-----END ... PRIVATE KEY-----</code>.
     *
     * @param inputPrivateKeyString the PKCS#8 formated private key
     * @param intputKeyType the key type or null
     * @return the private key
     * @throws GeneralSecurityException In case of general security exception
     */
    public PrivateKey getPrivateKey(String inputPrivateKeyString, String intputKeyType) throws GeneralSecurityException {
        if (inputPrivateKeyString == null || inputPrivateKeyString.isBlank()) {
            throw new GeneralSecurityException("Invalid private key!");
        }
        
        String keyType = intputKeyType;
        String privateKeyString = inputPrivateKeyString.trim();
        if (privateKeyString.startsWith(START_CERTIFICATE)) {
            int idx = privateKeyString.indexOf(END_PRIVATE_KEY, START_CERTIFICATE.length());
            if (idx < 0) {
                throw new GeneralSecurityException("Invalid private key!");
            }
            
            String readKeyType = privateKeyString.substring(START_CERTIFICATE.length() + 1, idx).trim();
            keyType = readKeyType;
            
        }

        if (keyType == null) {
            keyType = "RSA";
        }
        
        try {
            return KeyConverterFactory.getInstance().getConverter(keyType).getPrivateKey(privateKeyString);
        } catch (IOException e) {
            throw new GeneralSecurityException(e.getMessage(), e);
        }
    }

    
    /**
     * Get the public key from a PKCS#8 formated public key which is bounded at the beginning by
     * <code>-----BEGIN PUBLIC KEY-----</code>, and bounded at the end by <code>-----END PUBLIC KEY-----</code>.
     *
     * @param inputPublicKeyString the PKCS#8 formated public key
     * @return the public key
     * @throws GeneralSecurityException In case of general security exception
     */
    public PublicKey getPublicKey(String inputPublicKeyString) throws GeneralSecurityException {
        return getPublicKey(inputPublicKeyString, null);
    }
    
    
    /**
     * Get the public key from a PKCS#8 formated public key which is bounded at the beginning by
     * <code>-----BEGIN PUBLIC KEY-----</code>, and bounded at the end by <code>-----END PUBLIC KEY-----</code>.
     *
     * @param inputPublicKeyString the PKCS#8 formated public key
     * @param intputKeyType the key type or null
     * @return the public key
     * @throws GeneralSecurityException In case of general security exception
     */
    public PublicKey getPublicKey(String inputPublicKeyString, String intputKeyType) throws GeneralSecurityException {
        if (inputPublicKeyString == null || inputPublicKeyString.isBlank()) {
            throw new GeneralSecurityException("Invalid public key!");
        }
        
        String keyType = intputKeyType;
        String publicKeyString = inputPublicKeyString.trim();
        if (publicKeyString.startsWith(START_CERTIFICATE)) {
            int idx = publicKeyString.indexOf(END_PUBLIC_KEY, START_CERTIFICATE.length());
            if (idx < 0) {
                throw new GeneralSecurityException("Invalid public key!");
            }
            
            String readKeyType = publicKeyString.substring(START_CERTIFICATE.length() + 1, idx).trim();
            keyType = readKeyType;
            
        }

        if (keyType == null) {
            keyType = "RSA";
        }
        
        try {
            return KeyConverterFactory.getInstance().getConverter(keyType).getPublicKey(publicKeyString);
        } catch (IOException e) {
            throw new GeneralSecurityException(e.getMessage(), e);
        }
    }


    /**
     * Convert PKCS#7 certificates string into a certificate chain
     *
     * @param inputCertificate the certificate, a PKCS#7 (with base64 encoded) X509 certificates, which are each bounded at the 
     *        beginning by <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     * @return the trust key-store with added certificate
     * @throws GeneralSecurityException In case of general security exception
     */
    public X509Certificate[] getCertificate(String inputCertificate) throws GeneralSecurityException {
        if (inputCertificate == null || inputCertificate.isBlank()) {
            throw new GeneralSecurityException("Invalid certificate!");
        }
        
        String certificate = inputCertificate.trim();
        if (certificate.startsWith(START_CERTIFICATE)) {
            int idx = certificate.indexOf(END_CERTIFICATE_KEY, START_CERTIFICATE.length());
            if (idx < 0) {
                throw new GeneralSecurityException("Invalid certificate!");
            }
        }
        
        X509Certificate[] certificateChain = CertificateUtilFactory.getInstance().getConverter().getX509Certificates(certificate); 
        if (LOG.isDebugEnabled()) {
            PKIUtil.getInstance().processCertificate(LOG::debug, "Convert certificates:", certificateChain);
        }
        
        return certificateChain;
    }
}
