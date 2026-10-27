/*
 * KeyStoreUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.util;

import com.github.toolarium.common.security.ISecuredSecretValue;
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
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
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
    private volatile KeyStore cachedDefaultTrustKeyStore;


    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static final class HOLDER {
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
    public KeyStore createKeyStore(char[] password) throws GeneralSecurityException, IOException {
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
    public KeyStore createKeyStore(String fileName, char[] password) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType()); // TODO
        char[] pw = null;
        if (password != null && password.length > 0) {
            pw = password;
        }
        
        keyStore.load(null, pw);
        
        if (fileName != null && !fileName.isBlank()) {
            // store away the keystore.
            try (FileOutputStream fos = new FileOutputStream(fileName)) {
                keyStore.store(fos, pw);
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
    public KeyStore readPKCS12KeyStore(String fileName, ISecuredSecretValue password) throws GeneralSecurityException, IOException {
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
    public KeyStore readPKCS12KeyStore(String fileName, String provider, ISecuredSecretValue password) throws GeneralSecurityException, IOException {
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
    public KeyStore readKeyStore(String fileName, String type, String provider, ISecuredSecretValue password) throws GeneralSecurityException, IOException {
        if (fileName == null) {
            return null;
        }
        
        KeyStore ks;
        if (provider != null) {
            ks = KeyStore.getInstance(type, provider);
        } else {
            ks = KeyStore.getInstance(type);
        }
        
        try (InputStream in = new BufferedInputStream(new FileInputStream(new File(fileName)))) {
            withSecret(password, chars -> ks.load(in, chars));
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
    public CertificateStore readPKCS12KeyPair(String fileName, String provider, String alias, ISecuredSecretValue password) throws GeneralSecurityException, IOException {
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

        final PrivateKey[] privKeyHolder = {null};
        withSecret(password, chars -> privKeyHolder[0] = (PrivateKey) ks.getKey(alias, chars));
        final PrivateKey privKey = privKeyHolder[0];
        
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
    public KeyStore writePKCS12KeyStore(String fileName, String alias, PrivateKey privateKey, Certificate[] certificates, ISecuredSecretValue password) throws GeneralSecurityException, IOException {
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
    public KeyStore writePKCS12KeyStore(String fileName, String provider, String alias, PrivateKey privateKey, Certificate[] certificates, ISecuredSecretValue password) throws GeneralSecurityException, IOException {
        if (privateKey == null) {
            throw new GeneralSecurityException("Invalid private key!");
        }
        
        KeyStore ks = null;
        boolean alreadyLoaded = false;
        if (new File(fileName).exists()) {
            // an existing keystore which can not be read (e.g. wrong password) is not overwritten, otherwise its keys are lost
            LOG.info("Read existing keystore [" + fileName + "].");
            try {
                ks = readPKCS12KeyStore(fileName, provider, password);
            } catch (IOException e) {
                throw new IOException("Could not read existing keystore [" + fileName + "], it is not overwritten: " + e.getMessage(), e);
            } catch (GeneralSecurityException e) {
                throw new GeneralSecurityException("Could not read existing keystore [" + fileName + "], it is not overwritten: " + e.getMessage(), e);
            }
            alreadyLoaded = (ks != null);
        }

        if (ks == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Create new keystore [" + fileName + "].");
            }
            if (provider == null) {
                ks = KeyStore.getInstance(PKCS12);
            } else {
                ks = KeyStore.getInstance(PKCS12, provider);
            }
        }

        if (ks == null) {
            throw new GeneralSecurityException("Could not write keystore: " + fileName);
        }

        if (new File(fileName).exists()) {
            LOG.info("Overwriting existing keystore [" + fileName + "].");
        }

        final boolean initRequired = !alreadyLoaded;
        final KeyStore finalKs = ks;
        withSecret(password, chars -> {
            if (initRequired) {
                finalKs.load(null, chars);
            }
            finalKs.setKeyEntry(alias, privateKey, chars, certificates);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Write keystore [" + fileName + "].");
            }
            writeKeyStoreFile(finalKs, fileName, chars);
        });
        return ks;
    }


    /**
     * Write a key store atomically: it is written into a temporary file in the same directory, which is moved
     * to the target file afterwards. A crash while writing does not leave a broken key store. On POSIX file
     * systems the file can only be read and written by the owner.
     *
     * @param keyStore the key store
     * @param fileName the file name
     * @param password the password
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of error
     */
    private void writeKeyStoreFile(KeyStore keyStore, String fileName, char[] password) throws GeneralSecurityException, IOException {
        Path target = new File(fileName).getAbsoluteFile().toPath();
        Path directory = target.getParent();
        if (directory != null) {
            Files.createDirectories(directory);
        }

        // a temporary file is only readable and writable by the owner on POSIX file systems
        Path tempFile = Files.createTempFile(directory, target.getFileName().toString(), ".tmp");
        boolean moved = false;
        try {
            try (OutputStream out = new BufferedOutputStream(Files.newOutputStream(tempFile))) {
                keyStore.store(out, password);
                out.flush();
            }

            try {
                Files.move(tempFile, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tempFile, target, StandardCopyOption.REPLACE_EXISTING);
            }
            moved = true;
        } finally {
            if (!moved) {
                Files.deleteIfExists(tempFile);
            }
        }
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
    public KeyStore createPKCS12KeyStore(String provider, String alias, PrivateKey privateKey, Certificate[] certificates, ISecuredSecretValue password) throws GeneralSecurityException, IOException {
        if (privateKey == null) {
            throw new GeneralSecurityException("Invalid private key!");
        }
        
        KeyStore ks = null;
        if (LOG.isDebugEnabled()) {
            LOG.debug("Create new keystore...");
        }
        if (provider == null) {
            ks = KeyStore.getInstance(PKCS12);
        } else {
            ks = KeyStore.getInstance(PKCS12, provider);
        }

        final KeyStore finalKs = ks;
        withSecret(password, chars -> {
            finalKs.load(null, chars);
            finalKs.setKeyEntry(alias, privateKey, chars, certificates);
        });
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
        KeyStore result = cachedDefaultTrustKeyStore;
        if (result != null) {
            return result;
        }

        synchronized (this) {
            result = cachedDefaultTrustKeyStore;
            if (result != null) {
                return result;
            }

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

            cachedDefaultTrustKeyStore = trustManagerKeyStore;
            return trustManagerKeyStore;
        }
    }

    
    /**
     * Add a certificate to a copy of the default trust keystore. The shared default trust keystore is not changed,
     * see {@link #addCertificateToTrustKeystore(String, X509Certificate[], boolean)}.
     *
     * @param alias the alias
     * @param certificate the certificate
     * @return the new keystore which contains the default trusted certificates and the given certificate
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessable trust keystore
     */
    public KeyStore addCertificateToTrustKeystore(String alias, X509Certificate certificate) throws GeneralSecurityException, IOException {
        return addCertificateToTrustKeystore(alias, new X509Certificate[] {certificate}, false);
    }


    /**
     * Add a certificate chain to a copy of the default trust keystore. The shared default trust keystore is not changed,
     * see {@link #addCertificateToTrustKeystore(String, X509Certificate[], boolean)}.
     *
     * @param alias the alias
     * @param certificateChain the certificate chain
     * @return the new keystore which contains the default trusted certificates and the given certificate chain
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessable trust keystore
     */
    public KeyStore addCertificateToTrustKeystore(String alias, X509Certificate[] certificateChain) throws GeneralSecurityException, IOException {
        return addCertificateToTrustKeystore(alias, certificateChain, false);
    }


    /**
     * Add a certificate chain to the default trust keystore.
     *
     * <p>If <code>global</code> is false, the certificates are added to a copy of the default trust keystore: only the caller
     * which uses the returned keystore trusts them.</p>
     *
     * <p>If <code>global</code> is true, the certificates are added to the shared default trust keystore: every later user of
     * {@link #getDefaultTrustKeyStore()} in this JVM trusts them. Use this only on purpose. The shared keystore is replaced
     * (copy on write), so readers never see a keystore which is modified concurrently. Keystores which were returned before
     * are not changed. The JDK default <code>SSLContext</code> is not changed.</p>
     *
     * @param alias the alias
     * @param certificateChain the certificate chain
     * @param global true to add the certificates to the shared default trust keystore (JVM wide)
     * @return the keystore which contains the default trusted certificates and the given certificate chain
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of not accessable trust keystore
     */
    public KeyStore addCertificateToTrustKeystore(String alias, X509Certificate[] certificateChain, boolean global) throws GeneralSecurityException, IOException {
        if (!global) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Add certificate to a copy of the default trust store with alias " + alias + "...");
            }

            return addCertificateToKeystore(copyTrustKeyStore(getDefaultTrustKeyStore()), alias, certificateChain);
        }

        synchronized (this) {
            LOG.info("Add certificate to the shared default trust store with alias " + alias + " (JVM wide).");
            KeyStore trustKeyStore = addCertificateToKeystore(copyTrustKeyStore(getDefaultTrustKeyStore()), alias, certificateChain);
            cachedDefaultTrustKeyStore = trustKeyStore;
            return trustKeyStore;
        }
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
    public synchronized KeyStore addCertificateToKeystore(KeyStore keyStore, String inputAlias, X509Certificate[] certificateChain) throws GeneralSecurityException, IOException {
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
     * Copy the certificate entries of a trust keystore into a new keystore. Key entries are not copied.
     *
     * @param source the trust keystore to copy
     * @return the new keystore
     * @throws GeneralSecurityException In case of general security exception
     * @throws IOException In case of an I/O error
     */
    private KeyStore copyTrustKeyStore(KeyStore source) throws GeneralSecurityException, IOException {
        KeyStore copy = createKeyStore(null);
        for (String alias : Collections.list(source.aliases())) {
            if (source.isCertificateEntry(alias)) {
                copy.setCertificateEntry(alias, source.getCertificate(alias));
            }
        }
        return copy;
    }


    /**
     * Action which receives a temporary copy of a secret.
     */
    @FunctionalInterface
    private interface SecretAction {
        /**
         * Run the action with the given password chars.
         *
         * @param pw the password chars, or {@code null} if no secret is set
         * @throws GeneralSecurityException in case of error
         * @throws IOException in case of an I/O error
         */
        void run(char[] pw) throws GeneralSecurityException, IOException;
    }


    /**
     * Execute a secret action using the chars from the given secret value.
     * If the secret is null or has no value, the action is invoked with a null char array.
     *
     * @param secret the secret value
     * @param action the action to run
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an I/O error
     */
    private static void withSecret(ISecuredSecretValue secret, SecretAction action) throws GeneralSecurityException, IOException {
        if (secret == null || secret.getValue() == null) {
            action.run(null);
        } else {
            try {
                secret.getValue().useChars(chars -> {
                    try {
                        action.run(chars);
                    } catch (GeneralSecurityException | IOException e) {
                        throw new RuntimeException(e);
                    }
                    return null;
                });
            } catch (RuntimeException e) {
                Throwable c = e.getCause();
                if (c instanceof GeneralSecurityException) {
                    throw (GeneralSecurityException) c;
                }
                if (c instanceof IOException) {
                    throw (IOException) c;
                }
                throw e;
            }
        }
    }


    /**
     * Get a {@link TrustManager} which trust all certificates.
     *
     * <p><b>WARNING: This method disables all certificate validation and must only be used for testing purposes.
     * Using this in production enables man-in-the-middle attacks.</b></p>
     *
     * @return {@link TrustManager} which trust all certificates
     * @deprecated This method is insecure and should not be used in production. Use proper trust store configuration instead.
     */
    @Deprecated
    public TrustManager[] getTrustAllCertificateManager() {
        LOG.warn("Using trust-all certificate manager: this disables TLS certificate validation and is insecure!");
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
