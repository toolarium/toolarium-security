/*
 * CertificateStoreTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.certificate.util.PKIUtilTest;
import com.github.toolarium.security.keystore.util.KeyStoreUtilTest;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the {@link CertificateStore}.
 *  
 * @author patrick
 */
public class CertificateStoreTest {
    private static final Logger LOG = LoggerFactory.getLogger(CertificateStoreTest.class);
    
    
    /**
     * Read pkcs12 file store
     *
     * @throws GeneralSecurityException In case of an error
     * @throws IOException In case of an error
     */
    @Test
    public void testRead() throws GeneralSecurityException, IOException {
        CertificateStore certificateStore = new CertificateStore(Paths.get(PKIUtilTest.TEST_RESOURCE_PATH, KeyStoreUtilTest.PKCS12_TESTFILE).toString(), KeyStoreUtilTest.PKCS12_ALIAS, KeyStoreUtilTest.PKCS12_KEYSTORE_PASSWORD);
        assertNotNull(certificateStore);
        assertNotNull(certificateStore.getCertificates());
        assertNotNull(certificateStore.getKeyPair());
        PKIUtil.getInstance().processCertificate(LOG::debug, null, certificateStore.getCertificates());
        PKIUtil.getInstance().processPublicKeyInfo(LOG::debug, null, certificateStore.getKeyPair().getPublic());
        PKIUtil.getInstance().processPrivateKeyInfo(LOG::debug, null, certificateStore.getKeyPair().getPrivate());
    }

    
    /**
     * Read pkcs12 file store
     *
     * @throws GeneralSecurityException In case of an error
     * @throws IOException In case of an error
     */
    @Test
    public void testWrite() throws GeneralSecurityException, IOException {
        
        // cretae new certificate
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(PKIUtil.getInstance().generateKeyPair(null, "RSA", 2048), // new RSA 2048 
                                                                                                           "myTest",  // dn 
                                                                                                           "aaa",     //
                                                                                                           new Date(),// from now 
                                                                                                           2 * 365);  // 2 years
        
        assertNotNull(certificateStore);
        assertNotNull(certificateStore.getCertificates());
        assertNotNull(certificateStore.getKeyPair());

        final String fileName = "build/myfile";
        final String fileNameP12 = fileName + ".p12";
        certificateStore.write(fileNameP12, KeyStoreUtilTest.PKCS12_ALIAS, KeyStoreUtilTest.PKCS12_KEYSTORE_PASSWORD);
        certificateStore.writeCertificate(fileName);
        certificateStore.writePublicKey(fileName);
        certificateStore.writePrivateKey(fileName);

        CertificateStore certificateStore2 = new CertificateStore(fileNameP12, KeyStoreUtilTest.PKCS12_ALIAS, KeyStoreUtilTest.PKCS12_KEYSTORE_PASSWORD);
        assertNotNull(certificateStore2);
        assertNotNull(certificateStore2.getCertificates());
        assertNotNull(certificateStore2.getKeyPair());
        PKIUtil.getInstance().processCertificate(LOG::debug, null, certificateStore2.getCertificates());
        PKIUtil.getInstance().processPublicKeyInfo(LOG::debug, null, certificateStore2.getKeyPair().getPublic());
        PKIUtil.getInstance().processPrivateKeyInfo(LOG::debug, null, certificateStore2.getKeyPair().getPrivate());
    }


    /**
     * Read pkcs12 file store
     *
     * @throws GeneralSecurityException In case of an error
     * @throws IOException In case of an error
     */
    @Test
    public void testWriteFromParent() throws GeneralSecurityException, IOException {

        CertificateStore certificateStoreParent1 = 
                CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(PKIUtil.getInstance().generateKeyPair(null, "RSA", 2048), // new RSA 2048 
                                                                                            null, 
                                                                                            "myParent1",  // dn 
                                                                                            "aaa",     //
                                                                                            new Date(),// from now 
                                                                                            1);        // 1 day

        /*
        CertificateStore certificateStoreParent2 = 
            CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(PKIUtil.getInstance().generateKeyPair("RSA", 2048), // new RSA 2048 
                                                                                            certificateStoreParent1, 
                                                                                            "myParent2",  // dn 
                                                                                            "aaa",     //
                                                                                            new Date(),// from now 
                                                                                            1);        // 1 day
        */                                                                                                                 

        // load parent certificate
        //CertificateStore certificateStoreParent3 = new CertificateStore(Paths.get(PKIUtilTest.TEST_RESOURCE_PATH, PKIUtilTest.PKCS12_TESTFILE).toString(), PKIUtilTest.PKCS12_ALIAS, PKIUtilTest.PKCS12_KEYSTORE_PASSWORD);
        
        // cretae new certificate
        CertificateStore certificateStore = 
                CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(PKIUtil.getInstance().generateKeyPair(null, "RSA", 2048), // new RSA 2048 
                                                                                            certificateStoreParent1, 
                                                                                            "myTest",  // dn 
                                                                                            "aaa",     //
                                                                                            new Date(),// from now 
                                                                                            1);        // 1 day
        
        assertNotNull(certificateStore);
        assertNotNull(certificateStore.getCertificates());
        assertNotNull(certificateStore.getKeyPair());

        X509Certificate cert = CertificateUtilFactory.getInstance().geChainAnalyzer().getCertificateFor(certificateStore.getKeyPair().getPublic(), Arrays.asList(certificateStore.getCertificates()));
        assertNotNull(cert);
        List<X509Certificate> l = CertificateUtilFactory.getInstance().geChainAnalyzer().buildChainFor(certificateStore.getKeyPair().getPublic(), Arrays.asList(certificateStore.getCertificates()));
        assertNotNull(l);
        
        
        final String filename = "build/myfile.p12";
        certificateStore.write(filename, KeyStoreUtilTest.PKCS12_ALIAS, KeyStoreUtilTest.PKCS12_KEYSTORE_PASSWORD);

        CertificateStore certificateStore2 = new CertificateStore(filename, KeyStoreUtilTest.PKCS12_ALIAS, KeyStoreUtilTest.PKCS12_KEYSTORE_PASSWORD);
        assertNotNull(certificateStore2);
        assertNotNull(certificateStore2.getCertificates());
        assertNotNull(certificateStore2.getKeyPair());
        PKIUtil.getInstance().processCertificate(LOG::debug, null, certificateStore2.getCertificates());
        PKIUtil.getInstance().processPublicKeyInfo(LOG::debug, null, certificateStore2.getKeyPair().getPublic());
        PKIUtil.getInstance().processPrivateKeyInfo(LOG::debug, null, certificateStore2.getKeyPair().getPrivate());
    }
    
    
    /**
     * Read pkcs12 file store
     *
     * @throws GeneralSecurityException In case of an error
     * @throws IOException In case of an error
     */
    @Test
    public void testSelfSignedCertifcate() throws GeneralSecurityException, IOException {
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate("myCertificate");
        assertNotNull(certificateStore);
        assertNotNull(certificateStore.getCertificates());
        assertNotNull(certificateStore.getKeyPair());
    }
}
