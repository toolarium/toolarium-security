/*
 * KeyStoreUtilTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.github.toolarium.common.security.ISecuredValue;
import com.github.toolarium.common.security.SecuredValue;
import com.github.toolarium.security.certificate.X509CertificateGenerator;
import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.certificate.util.PKIUtil;
import java.io.FileOutputStream;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the {@link KeyStoreUtil}.
 *  
 * @author patrick
 */
public class KeyStoreUtilTest {
    
    /** Defines the PKCS12 test file */
    public static final String PKCS12_TESTFILE = "testpkcs12.p12";
    
    /** Defines the resource */
    public static final String TEST_RESOURCE_PATH = "src/test/resources";
    
    /** Defines the PKCS12 test password */
    public static final ISecuredValue<String> PKCS12_KEYSTORE_PASSWORD = new SecuredValue<String>("123456", "...");
    
    /** Defines the PKCS12 test alias */
    public static final String PKCS12_ALIAS = "Test";    
    private static final Logger LOG = LoggerFactory.getLogger(KeyStoreUtilTest.class);
    
    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void createNewKeyStoreInMemory() throws Exception {
        KeyStore ks = KeyStoreUtil.getInstance().createKeyStore(null);
        assertNotNull(ks);
        assertEquals("pkcs12", ks.getType());

        // create new certificate
        CertificateStore certificateStore = X509CertificateGenerator.getInstance().createCreateCertificate("myCertificate");
        assertNotNull(certificateStore);
        assertNotNull(certificateStore.getCertificates());

        // store certificate
        ks.setCertificateEntry(PKCS12_ALIAS, certificateStore.getCertificates()[0]);
        
        // verify certificate
        assertEquals(certificateStore.getCertificates()[0], ks.getCertificate(PKCS12_ALIAS));
    }

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void createNewKeyStoreStoredAsFile() throws Exception {
        String file = "build/keystore.p12";
        KeyStore ks1 = KeyStoreUtil.getInstance().createKeyStore(file, PKCS12_KEYSTORE_PASSWORD.getValue());
        assertNotNull(ks1);
        assertEquals("pkcs12", ks1.getType());

        // create new certificate
        CertificateStore certificateStore = X509CertificateGenerator.getInstance().createCreateCertificate("myCertificate");
        assertNotNull(certificateStore);
        assertNotNull(certificateStore.getCertificates());

        // store certificate
        ks1.setCertificateEntry(PKCS12_ALIAS, certificateStore.getCertificates()[0]);
        
        FileOutputStream fos = new FileOutputStream(file);
        ks1.store(fos, PKCS12_KEYSTORE_PASSWORD.getValue().toCharArray());
        fos.close();

        KeyStore ks2 = KeyStoreUtil.getInstance().readPKCS12KeyStore(file, PKCS12_KEYSTORE_PASSWORD);
        
        // verify certificate
        assertEquals(certificateStore.getCertificates()[0], ks2.getCertificate(PKCS12_ALIAS));
    }

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testPKCS12KeyStore() throws Exception {
        KeyStore ks = KeyStoreUtil.getInstance().readPKCS12KeyStore(Paths.get(TEST_RESOURCE_PATH, PKCS12_TESTFILE).toString(), null, PKCS12_KEYSTORE_PASSWORD);
        assertNotNull(ks);
        assertEquals("PKCS12", ks.getType());

        X509Certificate cert = (X509Certificate) ks.getCertificate(PKCS12_ALIAS);
        assertNotNull(cert);
        PKIUtil.getInstance().processCertificate(LOG::debug, null, cert);
        
        PrivateKey privKey = (PrivateKey) ks.getKey(PKCS12_ALIAS, PKCS12_KEYSTORE_PASSWORD.getValue().toCharArray());
        assertNotNull(privKey);
        PKIUtil.getInstance().processPrivateKeyInfo(LOG::debug, null, privKey);
    }

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testPKCS12KeyPair() throws Exception {
        CertificateStore h = KeyStoreUtil.getInstance().readPKCS12KeyPair(Paths.get(TEST_RESOURCE_PATH, PKCS12_TESTFILE).toString(), null, PKCS12_ALIAS, PKCS12_KEYSTORE_PASSWORD);
        assertNotNull(h);
        assertNotNull(h.getCertificates());

        KeyPair pair = h.getKeyPair();
        assertNotNull(pair);
        PKIUtil.getInstance().processPublicKeyInfo(LOG::debug, null, pair.getPublic());
        PKIUtil.getInstance().processPrivateKeyInfo(LOG::debug, null, pair.getPrivate());
    }

}
