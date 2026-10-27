/*
 * KeyStoreFindingsTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.common.security.ISecuredSecretValue;
import com.github.toolarium.common.security.SecuredValueFactory;
import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.certificate.impl.CertificateVerifier;
import com.github.toolarium.security.keystore.impl.SecurityManagerProviderImpl;
import com.github.toolarium.security.keystore.impl.ToolariumKeyManager;
import com.github.toolarium.security.keystore.impl.ToolariumTrustManager;
import com.github.toolarium.security.keystore.util.KeyStoreUtil;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509KeyManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;


/**
 * Test the key store findings (N32, N39, N40, N41, N42, N69, N70, N73, N75, N76, N77, N78, N79).
 *
 * @author patrick
 */
public class KeyStoreFindingsTest {
    private static final String HOST = "myhost.example.com";
    private static final String OTHER_HOST = "other.example.com";
    private static final String RSA = "RSA";
    private static final String ALIAS = "n41";
    private static final String PASSWORD = "secret";
    private static final String KEYSTORE_FILE = "test.p12";
    private static final String TEST_PKCS12_FILE = "src/test/resources/testpkcs12.p12";
    private static final String TEST_PKCS12_PASSWORD = "123456";
    private static final int PORT = 443;

    @TempDir
    private File tempDir;


    /**
     * Constructor for KeyStoreFindingsTest
     */
    public KeyStoreFindingsTest() {
        // NOP
    }


    /**
     * Without a configured host name the peer host of the engine is verified per check (N39); a blank host name
     * counts as not configured (N32).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testEnginePeerHost() throws Exception {
        X509Certificate[] chain = createCertificate(HOST).getCertificates();
        ToolariumTrustManager trustManager = new ToolariumTrustManager("  ");
        trustManager.addTrustedCertificate(chain[0]);

        assertDoesNotThrow(() -> trustManager.checkServerTrusted(chain, RSA, createEngine(HOST)));
        assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(chain, RSA, createEngine(OTHER_HOST)));
        assertDoesNotThrow(() -> trustManager.checkServerTrusted(chain, RSA, createEngine(HOST)));

        // the existing two argument method keeps its behaviour: no host name, no host name verification
        assertDoesNotThrow(() -> trustManager.checkServerTrusted(chain, RSA));
    }


    /**
     * An explicitly configured host name wins over the peer host of the connection (N39).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testConfiguredHostnameWins() throws Exception {
        X509Certificate[] chain = createCertificate(HOST).getCertificates();
        ToolariumTrustManager trustManager = new ToolariumTrustManager(HOST);
        trustManager.addTrustedCertificate(chain[0]);
        assertDoesNotThrow(() -> trustManager.checkServerTrusted(chain, RSA, createEngine(OTHER_HOST)));

        trustManager.setHostname(OTHER_HOST);
        assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(chain, RSA, createEngine(HOST)));
    }


    /**
     * The peer host of a socket is verified per check (N39).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testSocketPeerHost() throws Exception {
        X509Certificate[] chain = createCertificate(HOST).getCertificates();
        ToolariumTrustManager trustManager = new ToolariumTrustManager();
        trustManager.addTrustedCertificate(chain[0]);

        assertDoesNotThrow(() -> trustManager.checkServerTrusted(chain, RSA, createSocket(HOST)));
        assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(chain, RSA, createSocket(OTHER_HOST)));
    }


    /**
     * A successful check sets an own result value, not the "not checked" value (N73).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testCheckResult() throws Exception {
        X509Certificate[] chain = createCertificate(HOST).getCertificates();
        ToolariumTrustManager trustManager = new ToolariumTrustManager(HOST);
        assertEquals(0, trustManager.getCheckResult());

        trustManager.addTrustedCertificate(chain[0]);
        trustManager.checkServerTrusted(chain, RSA);
        int okResult = trustManager.getCheckResult();
        assertNotEquals(0, okResult);

        trustManager.setHostname(OTHER_HOST);
        assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(chain, RSA));
        assertNotEquals(0, trustManager.getCheckResult());
        assertNotEquals(okResult, trustManager.getCheckResult());
    }


    /**
     * The trust list of the verifier is only rebuilt for a new certificate (N40).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testTrustListOnlyRebuiltForNewCertificate() throws Exception {
        X509Certificate[] chain = createCertificate(HOST).getCertificates();
        ToolariumTrustManager trustManager = new ToolariumTrustManager(HOST);
        trustManager.addTrustedCertificate(chain[0]);

        Field field = ToolariumTrustManager.class.getDeclaredField("certificateVerifier");
        field.setAccessible(true);
        CertificateVerifier verifier = (CertificateVerifier) field.get(trustManager);
        Object trustList = verifier.getTrustedCertificates();

        trustManager.addTrustedCertificate(chain[0]);
        trustManager.checkServerTrusted(chain, RSA);
        assertSame(trustList, verifier.getTrustedCertificates());

        trustManager.addTrustedCertificate(createCertificate(OTHER_HOST).getCertificates()[0]);
        assertEquals(2, verifier.getTrustedCertificates().size());
    }


    /**
     * The key manager chooses an alias for an engine (N41).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testChooseEngineAlias() throws Exception {
        KeyStore keyStore = createCertificate(HOST).toKeyStore(ALIAS, PASSWORD.toCharArray());
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, PASSWORD.toCharArray());
        ToolariumKeyManager keyManager = new ToolariumKeyManager((X509KeyManager) keyManagerFactory.getKeyManagers()[0]);

        String serverAlias = keyManager.chooseServerAlias(RSA, null, null);
        assertNotNull(serverAlias);
        assertEquals(serverAlias, keyManager.chooseEngineServerAlias(RSA, null, createEngine(HOST)));
        assertEquals(keyManager.chooseClientAlias(new String[] {RSA}, null, null), keyManager.chooseEngineClientAlias(new String[] {RSA}, null, createEngine(HOST)));
    }


    /**
     * A null trust store file uses the default trust store and a null key store type the default type (N42);
     * a trust store file is read with the password (N70).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testDefaultTrustStoreAndType() throws Exception {
        File keyStoreFile = Paths.get(TEST_PKCS12_FILE).toFile();
        ISecurityManagerProvider provider = SecurityManagerProviderFactory.getInstance().getSecurityManagerProvider(null, keyStoreFile, createSecret(TEST_PKCS12_PASSWORD));
        assertTrue(provider.getTrustManagers().length > 0);
        assertTrue(provider.getKeyManagers().length > 0);

        assertNotNull(KeyStoreUtil.getInstance().readKeyStore(keyStoreFile.getPath(), null, null, createSecret(TEST_PKCS12_PASSWORD)));
        assertNotNull(SecurityManagerProviderFactory.getInstance().getSecurityManagerProvider(keyStoreFile, keyStoreFile, createSecret(TEST_PKCS12_PASSWORD), null));
    }


    /**
     * A destroyed password is not used as "no password" (N69).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testDestroyedPassword() throws Exception {
        ISecuredSecretValue destroyed = createSecret(TEST_PKCS12_PASSWORD);
        destroyed.destroy();
        assertThrows(GeneralSecurityException.class, () -> KeyStoreUtil.getInstance().readKeyStore(TEST_PKCS12_FILE, null, null, destroyed));

        KeyStore keyStore = createCertificate(HOST).toKeyStore(ALIAS, PASSWORD.toCharArray());
        assertThrows(GeneralSecurityException.class, () -> new SecurityManagerProviderImpl(null, keyStore, destroyed).getKeyManagers());
    }


    /**
     * A missing alias gives a clear exception (N75), a null password is treated as "no password" (N77).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testMissingAliasAndNullPassword() throws Exception {
        KeyStore keyStore = createCertificate(HOST).toKeyStore(ALIAS, PASSWORD.toCharArray());
        assertThrows(GeneralSecurityException.class, () -> SecurityManagerProviderFactory.getInstance().getSecurityManagerProvider(keyStore, PASSWORD.toCharArray(), "missing"));
        assertThrows(GeneralSecurityException.class, () -> SecurityManagerProviderFactory.getInstance().getSecurityManagerProvider(keyStore, PASSWORD.toCharArray(), null));
        assertNotNull(SecurityManagerProviderFactory.getInstance().getSecurityManagerProvider(keyStore, (char[]) null, ALIAS));
    }


    /**
     * Generated aliases do not overwrite existing entries (N76) and expired certificates are not added (N75).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testAliasCollision() throws Exception {
        X509Certificate first = createCertificate(HOST).getCertificates()[0];
        X509Certificate second = createCertificate(OTHER_HOST).getCertificates()[0];
        KeyStore keyStore = KeyStoreUtil.getInstance().createKeyStore(null);
        keyStore.setCertificateEntry("cert0", first);

        KeyStoreUtil.getInstance().addCertificateToKeystore(keyStore, "cert", new X509Certificate[] {second});
        assertEquals(first, keyStore.getCertificate("cert0"));
        assertNotNull(keyStore.getCertificateAlias(second));
        assertEquals(2, keyStore.size());

        // the same certificate with the same alias is not added twice
        KeyStoreUtil.getInstance().addCertificateToKeystore(keyStore, "cert", new X509Certificate[] {first});
        assertEquals(2, keyStore.size());

        // an expired certificate is not added
        Date startDate = new Date(System.currentTimeMillis() - 10L * 24 * 60 * 60 * 1000);
        X509Certificate expired = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate(PKIUtil.getInstance().generateKeyPair(null, RSA, 2048), "expired.example.com", null, startDate, 1).getCertificates()[0];
        KeyStoreUtil.getInstance().addCertificateToKeystore(keyStore, "expired", new X509Certificate[] {expired});
        assertEquals(2, keyStore.size());
    }


    /**
     * Writing a PKCS12 key store: invalid arguments give a clear exception and concurrent writers do not lose updates (N78).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testWritePKCS12KeyStore() throws Exception {
        CertificateStore store = createCertificate(HOST);
        String fileName = new File(tempDir, KEYSTORE_FILE).getPath();
        assertThrows(GeneralSecurityException.class,
            () -> KeyStoreUtil.getInstance().writePKCS12KeyStore(fileName, null, store.getKeyPair().getPrivate(), store.getCertificates(), createSecret(PASSWORD)));
        assertThrows(IOException.class,
            () -> KeyStoreUtil.getInstance().writePKCS12KeyStore(null, ALIAS, store.getKeyPair().getPrivate(), store.getCertificates(), createSecret(PASSWORD)));

        int writers = 4;
        ExecutorService executor = Executors.newFixedThreadPool(writers);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<KeyStore>> futures = new ArrayList<Future<KeyStore>>();
            for (int i = 0; i < writers; i++) {
                final String alias = ALIAS + i;
                futures.add(executor.submit(() -> {
                    start.await();
                    return KeyStoreUtil.getInstance().writePKCS12KeyStore(fileName, alias, store.getKeyPair().getPrivate(), store.getCertificates(), createSecret(PASSWORD));
                }));
            }
            start.countDown();
            for (Future<KeyStore> future : futures) {
                assertNotNull(future.get());
            }
        } finally {
            executor.shutdown();
        }

        KeyStore keyStore = KeyStoreUtil.getInstance().readPKCS12KeyStore(fileName, createSecret(PASSWORD));
        for (int i = 0; i < writers; i++) {
            assertTrue(keyStore.containsAlias(ALIAS + i));
        }
        assertEquals(1, tempDir.listFiles().length, "no temporary file left");
    }


    /**
     * Creating a key store file writes it atomically (N79).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testCreateKeyStoreFile() throws Exception {
        String fileName = new File(tempDir, KEYSTORE_FILE).getPath();
        assertNotNull(KeyStoreUtil.getInstance().createKeyStore(fileName, PASSWORD.toCharArray()));
        assertNotNull(KeyStoreUtil.getInstance().readKeyStore(fileName, null, null, createSecret(PASSWORD)));
        assertEquals(1, tempDir.listFiles().length, "no temporary file left");
    }


    /**
     * The shared default trust key store is read only (N38): it can be read and used, but not changed.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testDefaultTrustKeyStoreIsReadOnly() throws Exception {
        KeyStore defaultTrustKeyStore = KeyStoreUtil.getInstance().getDefaultTrustKeyStore();
        X509Certificate certificate = createCertificate("n38.example.com").getCertificates()[0];
        int size = defaultTrustKeyStore.size();

        assertThrows(java.security.KeyStoreException.class, () -> defaultTrustKeyStore.setCertificateEntry("n38", certificate));
        assertThrows(java.security.KeyStoreException.class, () -> defaultTrustKeyStore.deleteEntry(defaultTrustKeyStore.aliases().nextElement()));
        assertEquals(size, KeyStoreUtil.getInstance().getDefaultTrustKeyStore().size());

        // it can still be used to create trust managers and copies with an additional certificate
        javax.net.ssl.TrustManagerFactory trustManagerFactory = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(defaultTrustKeyStore);
        assertNotNull(trustManagerFactory.getTrustManagers());
        KeyStore copy = KeyStoreUtil.getInstance().addCertificateToTrustKeystore("n38", certificate);
        assertEquals(size + 1, copy.size());
        copy.setCertificateEntry("n38-copy", certificate);
    }


    /**
     * The host name is not verified for client certificates (N72).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testNoHostnameCheckForClientCertificates() throws Exception {
        X509Certificate certificate = createCertificate(HOST).getCertificates()[0];
        ToolariumTrustManager trustManager = new ToolariumTrustManager(OTHER_HOST);
        trustManager.addTrustedCertificate(certificate);
        assertDoesNotThrow(() -> trustManager.checkClientTrusted(new X509Certificate[] {certificate}, RSA));
        assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(new X509Certificate[] {certificate}, RSA));
    }


    /**
     * An IP address only matches an IP address subject alternative name, compared as address (N71).
     *
     * @throws Exception in case of error
     */
    @Test
    public void testIpAddressHostname() throws Exception {
        HostnameMatcher matcher = new HostnameMatcher();

        // a DNS name or common name which looks like an IP address does not match the IP address
        X509Certificate dnsCertificate = createCertificate("127.0.0.1").getCertificates()[0];
        assertTrue(matcher.matches(dnsCertificate, "localhost"));
        assertTrue(!matcher.matches(dnsCertificate, "127.0.0.1"));

        // IP address subject alternative names
        X509Certificate ipCertificate = createIpCertificate("10.1.2.3", "::1");
        assertTrue(matcher.matches(ipCertificate, "10.1.2.3"));
        assertTrue(matcher.matches(ipCertificate, "0:0:0:0:0:0:0:1"));
        assertTrue(matcher.matches(ipCertificate, "[::1]"));
        assertTrue(!matcher.matches(ipCertificate, "10.1.2.4"));
        assertTrue(!matcher.matches(ipCertificate, "ip.example.com"));
    }


    /**
     * Create a self-signed certificate with IP address subject alternative names.
     *
     * @param ipAddresses the IP addresses
     * @return the certificate
     * @throws Exception in case of error
     */
    private X509Certificate createIpCertificate(String... ipAddresses) throws Exception {
        java.security.KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(null, RSA, 2048);
        org.bouncycastle.asn1.x500.X500Name name = new org.bouncycastle.asn1.x500.X500Name("CN=ip-test");
        org.bouncycastle.asn1.x509.GeneralName[] names = new org.bouncycastle.asn1.x509.GeneralName[ipAddresses.length];
        for (int i = 0; i < ipAddresses.length; i++) {
            names[i] = new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.iPAddress, ipAddresses[i]);
        }

        Date now = new Date();
        org.bouncycastle.cert.X509v3CertificateBuilder builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                name, java.math.BigInteger.ONE, now, new Date(now.getTime() + 86_400_000L), name, keyPair.getPublic());
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, new org.bouncycastle.asn1.x509.GeneralNames(names));
        org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }


    /**
     * Trust manager which makes the host name matching accessible for the test.
     */
    private static final class HostnameMatcher extends ToolariumTrustManager {
        /**
         * Check if the certificate matches the host name.
         *
         * @param certificate the certificate
         * @param host the host name
         * @return true if it matches
         * @throws CertificateException in case of error
         */
        boolean matches(X509Certificate certificate, String host) throws CertificateException {
            return matchesHostname(certificate, host);
        }
    }


    /**
     * Create a self-signed certificate
     *
     * @param dn the dn
     * @return the certificate store
     * @throws Exception in case of error
     */
    private CertificateStore createCertificate(String dn) throws Exception {
        return CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(dn);
    }


    /**
     * Create a client engine for the given peer host (no handshake session).
     *
     * @param peerHost the peer host
     * @return the engine
     * @throws Exception in case of error
     */
    private SSLEngine createEngine(String peerHost) throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        SSLEngine engine = sslContext.createSSLEngine(peerHost, PORT);
        engine.setUseClientMode(true);
        return engine;
    }


    /**
     * Create an unconnected socket which reports the given remote host.
     *
     * @param peerHost the peer host
     * @return the socket
     * @throws Exception in case of error
     */
    private Socket createSocket(String peerHost) throws Exception {
        final InetAddress address = InetAddress.getByAddress(peerHost, new byte[] {127, 0, 0, 1});
        return new Socket() {
            /**
             * @see java.net.Socket#getInetAddress()
             */
            @Override
            public InetAddress getInetAddress() {
                return address;
            }
        };
    }


    /**
     * Create a secret
     *
     * @param password the password
     * @return the secret
     */
    private ISecuredSecretValue createSecret(String password) {
        return SecuredValueFactory.getInstance().createSecret(password.toCharArray());
    }
}
