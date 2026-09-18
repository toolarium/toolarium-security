/*
 * CertificateChainAnalyzerTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.certificate.dto.CertificateStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the {@link ICertificateChainAnalyzer}.
 *
 * @author patrick
 */
public class CertificateChainAnalyzerTest {
    private static final Logger LOG = LoggerFactory.getLogger(CertificateChainAnalyzerTest.class);


    /**
     * Test isSelfSigned detects a self-signed certificate
     *
     * @throws Exception in case of error
     */
    @Test
    public void testIsSelfSigned() throws Exception {
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("TestChainSelfSigned");
        X509Certificate cert = certificateStore.getCertificates()[0];

        ICertificateChainAnalyzer analyzer = CertificateUtilFactory.getInstance().geChainAnalyzer();
        assertTrue(analyzer.isSelfSigned(cert));
    }


    /**
     * Test getCertificateFor returns the certificate matching the given public key
     *
     * @throws Exception in case of error
     */
    @Test
    public void testGetCertificateFor() throws Exception {
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("TestGetCertFor");
        X509Certificate cert = certificateStore.getCertificates()[0];

        ICertificateChainAnalyzer analyzer = CertificateUtilFactory.getInstance().geChainAnalyzer();
        X509Certificate found = analyzer.getCertificateFor(certificateStore.getKeyPair().getPublic(),
                Arrays.asList(certificateStore.getCertificates()));
        assertNotNull(found);
        assertEquals(cert, found);
    }


    /**
     * Test getCertificateFor returns null when the key is not present in the collection
     *
     * @throws Exception in case of error
     */
    @Test
    public void testGetCertificateForNotFound() throws Exception {
        CertificateStore certificateStore1 = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("TestGetCertForMiss1");
        CertificateStore certificateStore2 = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("TestGetCertForMiss2");

        ICertificateChainAnalyzer analyzer = CertificateUtilFactory.getInstance().geChainAnalyzer();
        // look for cert2's key in cert1's collection — should return null
        X509Certificate found = analyzer.getCertificateFor(certificateStore2.getKeyPair().getPublic(),
                Arrays.asList(certificateStore1.getCertificates()));
        assertNull(found);
    }


    /**
     * Test buildChainFor a single self-signed certificate returns a list with that certificate
     *
     * @throws Exception in case of error
     */
    @Test
    public void testBuildChainForSelfSigned() throws Exception {
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("TestBuildChain");

        ICertificateChainAnalyzer analyzer = CertificateUtilFactory.getInstance().geChainAnalyzer();
        List<X509Certificate> chain = analyzer.buildChainFor(certificateStore.getKeyPair(),
                Arrays.asList(certificateStore.getCertificates()));
        assertNotNull(chain);
        assertTrue(chain.size() >= 1);

        LOG.debug("Chain length: " + chain.size());
    }


    /**
     * Test getPrincipals returns the correct number of principals for the chain
     *
     * @throws Exception in case of error
     */
    @Test
    public void testGetPrincipals() throws Exception {
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate("TestPrincipals");

        ICertificateChainAnalyzer analyzer = CertificateUtilFactory.getInstance().geChainAnalyzer();
        List<X509Certificate> chain = analyzer.buildChainFor(certificateStore.getKeyPair(),
                Arrays.asList(certificateStore.getCertificates()));

        javax.security.auth.x500.X500Principal[] principals = analyzer.getPrincipals(chain);
        assertNotNull(principals);
        assertEquals(chain.size(), principals.length);
    }
}
