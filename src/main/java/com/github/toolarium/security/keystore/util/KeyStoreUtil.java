/*
 * KeyStoreUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.util;

import com.github.toolarium.common.security.ISecuredValue;
import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * {@link KeyStore} util class. 
 * 
 * @author patrick
 */
public final class KeyStoreUtil {
    private static final String PKCS12 = "PKCS12";
    private static final Logger LOG = LoggerFactory.getLogger(KeyStoreUtil.class);


    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final KeyStoreUtil INSTANCE = new KeyStoreUtil();
    }

    
    /**
     * Constructor
     */
    private KeyStoreUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static KeyStoreUtil getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Create a new keystore
     *
     * @param password the password or null
     * @return the new keystore
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    public KeyStore createKeyStore(String password) throws GeneralSecurityException, IOException {
        return createKeyStore(null, password);
    }

    
    /**
     * Create a new keystore
     *
     * @param fileName the filename
     * @param password the password or null
     * @return the new keystore
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    public KeyStore createKeyStore(String fileName, String password) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType()); // TODO
        char[] pw = null;
        if (password != null && !password.isBlank()) {
            pw = password.toCharArray();
        }
        
        keyStore.load(null, pw);
        
        if (fileName != null && !fileName.isBlank()) {
            // store away the keystore.
            FileOutputStream fos = null;
            try {
                fos = new FileOutputStream(fileName);
                keyStore.store(fos, pw);
            } finally {
                if (fos != null) {
                    try {
                        fos.close();
                    } catch (IOException e) {
                        // NOP
                    }
                }
            }
        }
        
        return keyStore;
    }    

    
    /**
     * Read a PKCS12 file as key store
     *
     * @param fileName the file to read
     * @param password the password or null
     * @return the key pairs
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    public KeyStore readPKCS12KeyStore(String fileName, ISecuredValue<String> password) throws GeneralSecurityException, IOException {
        return readKeyStore(fileName, PKCS12, null, password);
    }

    
    /**
     * Read a PKCS12 file as key store
     *
     * @param fileName the file to read
     * @param provider the provider or null
     * @param password the password or null
     * @return the key pairs
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    public KeyStore readPKCS12KeyStore(String fileName, String provider, ISecuredValue<String> password) throws GeneralSecurityException, IOException {
        return readKeyStore(fileName, PKCS12, provider, password);
    }

    
    /**
     * Read a file as key store
     *
     * @param fileName the file to read
     * @param type the key store type
     * @param provider the provider or null
     * @param password the password or null
     * @return the key pairs
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    public KeyStore readKeyStore(String fileName, String type, String provider, ISecuredValue<String> password) throws GeneralSecurityException, IOException {
        if (fileName == null) {
            return null;
        }
        
        KeyStore ks;
        if (provider != null) {
            ks = KeyStore.getInstance(type, provider);
        } else {
            ks = KeyStore.getInstance(type);
        }
        
        InputStream in = new BufferedInputStream(new FileInputStream(new File(fileName)));
        if (password != null && password.getValue() != null) {
            ks.load(in, password.getValue().toCharArray());
        } else {
            ks.load(in, null);
        }
        
        return ks;
    }


    /**
     * Read a PKCS12 file as key store
     *
     * @param fileName the file to read
     * @param provider the provider or null
     * @param alias the alias in the PKCS12 file
     * @param password the password or null
     * @return the certificate store
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of error
     */
    public CertificateStore readPKCS12KeyPair(String fileName, String provider, String alias, ISecuredValue<String> password) throws GeneralSecurityException, IOException {
        if (fileName == null) {
            return null;
        }
            
        KeyStore ks = readPKCS12KeyStore(fileName, provider, password);
        if (ks == null) {
            throw new GeneralSecurityException("Could not read key keystore: " + fileName);
        }
        
        if (alias == null) {
            throw new GeneralSecurityException("Invalid alias!");
        }
        
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        if (cert == null) {
            throw new GeneralSecurityException("Could not read the certificate from keystore: " + fileName);
        }

        final PrivateKey privKey;
        if (password != null && password.getValue() != null) {
            privKey = (PrivateKey) ks.getKey(alias, password.getValue().toCharArray());
        } else {
            privKey = (PrivateKey) ks.getKey(alias, null);
        }
        
        if (privKey == null) {
            throw new GeneralSecurityException("Could not read the private key from keystore: " + fileName);
        }
        
        return new CertificateStore(new KeyPair(cert.getPublicKey(), privKey), cert);
    }


    /**
     * Writes a PKCS12 file as key store
     *
     * @param fileName the file to read
     * @param alias the alias in the PKCS12 file or null
     * @param privateKey the private key
     * @param certificates the certificate chain
     * @param password the password or null
     * @return the written key store
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of error
     */
    public KeyStore writePKCS12KeyStore(String fileName, String alias, PrivateKey privateKey, Certificate[] certificates, ISecuredValue<String> password) throws GeneralSecurityException, IOException {
        return writePKCS12KeyStore(fileName, null, alias, privateKey, certificates, password);
    }

    
    /**
     * Writes a PKCS12 file as key store
     *
     * @param fileName the file to read
     * @param provider the provider or null
     * @param alias the alias in the PKCS12 file or null
     * @param privateKey the private key
     * @param certificates the certificate chain
     * @param password the password or null
     * @return the written key store
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of error
     */
    public KeyStore writePKCS12KeyStore(String fileName, String provider, String alias, PrivateKey privateKey, Certificate[] certificates, ISecuredValue<String> password) throws GeneralSecurityException, IOException {
        if (privateKey == null) {
            throw new GeneralSecurityException("Invalid private key!");
        }
        
        KeyStore ks = null;
        if (new File(fileName).exists()) {
            try {
                LOG.info("Read existing keystore [" + fileName + "].");
                ks = readPKCS12KeyStore(fileName, provider, password);
            } catch (IOException e) {
                LOG.error("Invalid keystore: " + fileName);
            }
        }

        if (ks == null) {
            LOG.debug("Create new keystore [" + fileName + "].");
            if (provider == null) {
                ks = KeyStore.getInstance(PKCS12);
            } else {
                ks = KeyStore.getInstance(PKCS12, provider);
            }
        }

        if (ks == null) {
            throw new GeneralSecurityException("Could not write keystore: " + fileName);
        }

        char[] pw = null;
        if (password != null && password.getValue() != null) {
            pw = password.getValue().toCharArray();
        }

        // for initializing the keystore
        if (pw != null) {
            ks.load(null, pw);

        } else {
            ks.load(null, null);
        }
        
        ks.setKeyEntry(alias, privateKey, pw, certificates);
        //ks.setKeyEntry(alias, privateKey.getEncoded(), certificates);

        OutputStream out = null;
        try {
            LOG.debug("Write keystore [" + fileName + "].");
            out = new BufferedOutputStream(new FileOutputStream(new File(fileName)));
            ks.store(out, pw);
            out.flush();
        } finally {
            if (out != null) {
                out.close();
            }
        }
        
        return ks;
    }


    /**
     * Create a PKCS12 key store
     *
     * @param provider the provider or null
     * @param alias the alias in the PKCS12 file or null
     * @param privateKey the private key
     * @param certificates the certificate chain
     * @param password the password or null
     * @return the written key store
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of error
     */
    public KeyStore createPKCS12KeyStore(String provider, String alias, PrivateKey privateKey, Certificate[] certificates, ISecuredValue<String> password) throws GeneralSecurityException, IOException {
        if (privateKey == null) {
            throw new GeneralSecurityException("Invalid private key!");
        }
        
        KeyStore ks = null;
        LOG.debug("Create new keystore...");
        if (provider == null) {
            ks = KeyStore.getInstance(PKCS12);
        } else {
            ks = KeyStore.getInstance(PKCS12, provider);
        }

        char[] pw = null;
        if (password != null && password.getValue() != null) {
            pw = password.getValue().toCharArray();
        }

        // for initialising the key store
        if (pw != null) {
            ks.load(null, pw);
        } else {
            ks.load(null, null);
        }
        
        //ks.setKeyEntry(alias, privateKey.getEncoded(), certificates);
        ks.setKeyEntry(alias, privateKey, pw, certificates);
        return ks;
    }

    
    /**
     * Get default {@link TrustManager}.
     *
     * @return the default trust manager or null
     * @throws GeneralSecurityException in case of error
     */
    public X509TrustManager getDefaultX509TrustManager() throws GeneralSecurityException {
        for (TrustManager tm : getDefaultTrustManager()) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }
        
        return null;
    }

    
    /**
     * Get default {@link TrustManager}.
     *
     * @return the default trust managers
     * @throws GeneralSecurityException in case of error
     */
    public TrustManager[] getDefaultTrustManager() throws GeneralSecurityException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        return tmf.getTrustManagers();
    }

    
    /**
     * Get default trust keystore
     *
     * @return the trust keystore
     * @throws GeneralSecurityException in case of error
     * @throws IOException In case of an I/O error
     */
    public KeyStore getDefaultTrustKeyStore() throws GeneralSecurityException, IOException {
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

        return trustManagerKeyStore;
    }

    
    /**
     * Add a certificate to the default trust keystore
     *
     * @param alias the alias
     * @param certificate the certificate
     * @return the keystore
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessable trust keystore
     */
    public KeyStore addCertificateToTrustKeystore(String alias, X509Certificate certificate) throws GeneralSecurityException, IOException {
        return addCertificateToTrustKeystore(alias, new X509Certificate[] {certificate});
    }

    
    /**
     * Add a certificate chain to the default trust keystore
     *
     * @param alias the alias
     * @param certificateChain the certificate chain
     * @return the keystore
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessable trust keystore
     */
    public KeyStore addCertificateToTrustKeystore(String alias, X509Certificate[] certificateChain) throws GeneralSecurityException, IOException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Add self-signed certificate to trust store with alias " + alias + "...");
        }
        
        return addCertificateToKeystore(getDefaultTrustKeyStore(), alias, certificateChain);
    }

    
    /**
     * Add a certificate chain to the keystore
     *
     * @param keyStore the key store
     * @param inputAlias the alias
     * @param certificateChain the certificate chain
     * @return the keystore
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessable trust keystore
     */
    public KeyStore addCertificateToKeystore(KeyStore keyStore, String inputAlias, X509Certificate[] certificateChain) throws GeneralSecurityException, IOException {
        if (keyStore != null && certificateChain != null) {
            String alias = inputAlias;
            if (alias == null) {
                alias = "";
            }
            
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
        }
        
        return keyStore;
    }

    
    /**
     * Get a {@link TrustManager} which trust all certificates 
     *
     * @return {@link TrustManager} which trust all certificates
     */
    public TrustManager[] getTrustAllCertificateManager() {
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                    /**
                     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
                     */
                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    
                    /**
                     * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
                     */
                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        // NOP
                    }

                    
                    /**
                     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String)
                     */
                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        // NOP
                    }
                } };
        return trustAllCerts;
    }
}
