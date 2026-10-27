/*
 * KeyStoreUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.util;

import com.github.toolarium.common.security.ISecuredSecretValue;
import com.github.toolarium.common.security.SecureSecret;
import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
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
import java.util.concurrent.ConcurrentHashMap;
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
    private static final ConcurrentHashMap<String, Object> FILE_LOCKS = new ConcurrentHashMap<String, Object>();
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
        
        if (fileName != null && !fileName.trim().isEmpty()) {
            // store away the keystore (atomic and only accessible by the owner)
            writeKeyStoreFile(keyStore, fileName, pw);
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
     * @param type the key store type or null to use the default type ({@link KeyStore#getDefaultType()})
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

        String keyStoreType = type;
        if (keyStoreType == null) {
            keyStoreType = KeyStore.getDefaultType();
        }

        KeyStore ks;
        if (provider != null) {
            ks = KeyStore.getInstance(keyStoreType, provider);
        } else {
            ks = KeyStore.getInstance(keyStoreType);
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
     * @param alias the alias in the PKCS12 file
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
     * @param alias the alias in the PKCS12 file
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

        if (fileName == null) {
            throw new IOException("Invalid file name!");
        }

        if (alias == null) {
            throw new GeneralSecurityException("Invalid alias!");
        }

        // the read-modify-write of the same file is serialized within the JVM, otherwise concurrent updates are lost
        synchronized (getFileLock(fileName)) {
            return updatePKCS12KeyStore(fileName, provider, alias, privateKey, certificates, password);
        }
    }


    /**
     * Adds the private key and certificate chain to a PKCS12 file: an existing file is read and updated, otherwise a new file is created.
     *
     * @param fileName the file to update
     * @param provider the provider or null
     * @param alias the alias in the PKCS12 file
     * @param privateKey the private key
     * @param certificates the certificate chain
     * @param password the password or null
     * @return the written key store
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of error
     */
    private KeyStore updatePKCS12KeyStore(String fileName, String provider, String alias, PrivateKey privateKey, Certificate[] certificates, ISecuredSecretValue password) throws GeneralSecurityException, IOException {
        KeyStore ks = null;
        boolean alreadyLoaded = false;
        if (new File(fileName).exists()) {
            // an existing keystore which can not be read (e.g. wrong password) is not overwritten, otherwise its keys are lost
            LOG.info("Read existing keystore [{}].", fileName);
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
                LOG.debug("Create new keystore [{}].", fileName);
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
            LOG.info("Overwriting existing keystore [{}].", fileName);
        }

        final boolean initRequired = !alreadyLoaded;
        final KeyStore finalKs = ks;
        withSecret(password, chars -> {
            if (initRequired) {
                finalKs.load(null, chars);
            }
            finalKs.setKeyEntry(alias, privateKey, chars, certificates);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Write keystore [{}].", fileName);
            }
            writeKeyStoreFile(finalKs, fileName, chars);
        });
        return ks;
    }


    /**
     * Get the lock object of a file. The same canonical file path always returns the same lock object within the JVM.
     *
     * @param fileName the file name
     * @return the lock object
     * @throws IOException in case the canonical path can not be resolved
     */
    private static Object getFileLock(String fileName) throws IOException {
        return FILE_LOCKS.computeIfAbsent(new File(fileName).getCanonicalPath(), key -> new Object());
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
            try (FileChannel channel = FileChannel.open(tempFile, StandardOpenOption.WRITE);
                 OutputStream out = new BufferedOutputStream(Channels.newOutputStream(channel))) {
                keyStore.store(out, password);
                out.flush();
                // the content must be on the disk before the move, otherwise a crash can leave an empty key store
                channel.force(true);
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
     * Get default trust keystore. The returned keystore is shared in the JVM and read only: a change throws a
     * {@link java.security.KeyStoreException}. To change it on purpose use
     * {@link #addCertificateToTrustKeystore(String, X509Certificate[], boolean)}.
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
            if (defaultTm == null) {
                throw new GeneralSecurityException("No default X509 trust manager found!");
            }

            X509Certificate[] trustedIssuers = defaultTm.getAcceptedIssuers();
            if (trustedIssuers != null) {
                int i = 1;

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Init new default trust stire with default trusted issuers: {}", trustedIssuers.length);
                }

                for (X509Certificate trustedIssuer : trustedIssuers) {
                    // add the key manager store in the trust store
                    trustManagerKeyStore.setCertificateEntry(getFreeAlias(trustManagerKeyStore, "cert" + i++, trustedIssuer), trustedIssuer);

                    //if (LOG.isDebugEnabled()) {
                    //    PKIUtil.getInstance().processCertificate(LOG::debug, "Add certificate to trust store:", trustedIssuers);
                    //}
                }
            }

            // the shared keystore is read only: a caller can not change the trust of the whole JVM by accident
            result = new ReadOnlyKeyStore(trustManagerKeyStore);
            cachedDefaultTrustKeyStore = result;
            return result;
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
                LOG.debug("Add certificate to a copy of the default trust store with alias {}...", alias);
            }

            return addCertificateToKeystore(copyTrustKeyStore(getDefaultTrustKeyStore()), alias, certificateChain);
        }

        synchronized (this) {
            LOG.info("Add certificate to the shared default trust store with alias {} (JVM wide).", alias);
            KeyStore trustKeyStore = new ReadOnlyKeyStore(addCertificateToKeystore(copyTrustKeyStore(getDefaultTrustKeyStore()), alias, certificateChain));
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
                for (X509Certificate expiredCertificate : CertificateUtilFactory.getInstance().getFilter().filterExpired(Arrays.asList(certificateChain))) {
                    LOG.warn("Expired certificate [{}] (expired {}) is not added to the key store (alias {}).", expiredCertificate.getSubjectX500Principal(), expiredCertificate.getNotAfter(), alias);
                }

                for (int i = 0; i < list.size(); i++) {
                    // add the key manager store in the store; an existing entry with a different certificate is not overwritten
                    keyStore.setCertificateEntry(getFreeAlias(keyStore, alias + i, list.get(i)), list.get(i));
                    if (LOG.isDebugEnabled()) {
                        PKIUtil.getInstance().processCertificate(LOG::debug, "Add certificate to key store:", list.get(i));
                    }
                }
            }
        }

        return keyStore;
    }


    /**
     * Get a free alias for a certificate entry: the alias itself if it is not used or if it is a certificate entry with the
     * same certificate, otherwise the alias with the suffix _1, _2, ... An existing entry is never overwritten with a
     * different certificate.
     *
     * @param keyStore the key store
     * @param alias the alias
     * @param certificate the certificate to add
     * @return the alias to use
     * @throws GeneralSecurityException In case of general security exception
     */
    private String getFreeAlias(KeyStore keyStore, String alias, Certificate certificate) throws GeneralSecurityException {
        String result = alias;
        int counter = 1;
        while (keyStore.containsAlias(result) && !(keyStore.isCertificateEntry(result) && certificate.equals(keyStore.getCertificate(result)))) {
            result = alias + "_" + counter;
            counter++;
        }
        return result;
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
     * If the secret is null, the action is invoked with a null char array.
     *
     * @param secret the secret value
     * @param action the action to run
     * @throws GeneralSecurityException in case of error or if the secret is destroyed
     * @throws IOException in case of an I/O error
     */
    private static void withSecret(ISecuredSecretValue secret, SecretAction action) throws GeneralSecurityException, IOException {
        if (secret == null) {
            action.run(null);
        } else {
            // read the value only once: a destroyed secret must not be used as "no password"
            SecureSecret value = secret.getValue();
            if (value == null || value.isDestroyed()) {
                throw new GeneralSecurityException("The password is destroyed!");
            }

            try {
                value.useChars(chars -> {
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
