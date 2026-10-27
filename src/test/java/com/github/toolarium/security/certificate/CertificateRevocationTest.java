/*
 * CertificateRevocationTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.certificate.impl.CertificateVerifier;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


/**
 * Test the revocation check of the {@link CertificateVerifier} with a CRL which is served by a local HTTP server (N10).
 *
 * @author patrick
 */
public class CertificateRevocationTest {
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String CA_DN = "CN=Test Revocation CA";
    private static final long ONE_HOUR = 60L * 60L * 1000L;
    private static final long ONE_DAY = 24L * ONE_HOUR;
    private HttpServer httpServer;
    private volatile byte[] crl;
    private KeyPair caKeyPair;
    private X509Certificate caCertificate;
    private String crlUrl;


    /**
     * Constructor for CertificateRevocationTest
     */
    public CertificateRevocationTest() {
        // NOP
    }


    /**
     * Start the local CRL server and create the CA.
     *
     * @throws Exception in case of error
     */
    @BeforeEach
    public void setUp() throws Exception {
        httpServer = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        httpServer.createContext("/ca.crl", exchange -> {
            byte[] content = crl;
            exchange.getResponseHeaders().add("Content-Type", "application/pkix-crl");
            exchange.sendResponseHeaders(200, content.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(content);
            }
        });
        httpServer.start();
        crlUrl = "http://127.0.0.1:" + httpServer.getAddress().getPort() + "/ca.crl";

        caKeyPair = createKeyPair();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(CA_DN), BigInteger.ONE, new Date(System.currentTimeMillis() - ONE_HOUR),
                new Date(System.currentTimeMillis() + ONE_DAY), new X500Name(CA_DN), caKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        caCertificate = new JcaX509CertificateConverter().getCertificate(builder.build(createSigner()));
    }


    /**
     * Stop the local CRL server.
     */
    @AfterEach
    public void tearDown() {
        if (httpServer != null) {
            httpServer.stop(0);
        }
    }


    /**
     * A revoked certificate is rejected, also in the default (not strict) mode.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRevokedCertificateIsRejected() throws Exception {
        X509Certificate leaf = createLeaf(BigInteger.valueOf(1000), true);
        crl = createCrl(BigInteger.valueOf(1000));

        CertificateVerifier verifier = CertificateUtilFactory.getInstance().createVerifier(true);
        CertPathValidatorException e = assertThrows(CertPathValidatorException.class,
                () -> verifier.verifyCertificateChain(null, new X509Certificate[] {leaf, caCertificate}));
        assertTrue(e.getReason() == CertPathValidatorException.BasicReason.REVOKED, "Unexpected reason: " + e.getReason());
    }


    /**
     * A certificate which is not on the CRL is accepted.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testValidCertificateIsAccepted() throws Exception {
        X509Certificate leaf = createLeaf(BigInteger.valueOf(1001), true);
        crl = createCrl(BigInteger.valueOf(9999));

        CertificateVerifier verifier = CertificateUtilFactory.getInstance().createVerifier(true);
        verifier.setRevocationStrict(true);
        assertDoesNotThrow(() -> verifier.verifyCertificateChain(null, new X509Certificate[] {leaf, caCertificate}));
    }


    /**
     * A certificate with an unknown revocation status is accepted by default and rejected in strict mode.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testUnknownRevocationStatus() throws Exception {
        X509Certificate leaf = createLeaf(BigInteger.valueOf(1002), false);

        CertificateVerifier verifier = CertificateUtilFactory.getInstance().createVerifier(true);
        assertDoesNotThrow(() -> verifier.verifyCertificateChain(null, new X509Certificate[] {leaf, caCertificate}));

        verifier.setRevocationStrict(true);
        assertThrows(CertPathValidatorException.class, () -> verifier.verifyCertificateChain(null, new X509Certificate[] {leaf, caCertificate}));
    }


    /**
     * Create a leaf certificate signed by the CA.
     *
     * @param serial the serial number
     * @param withCrlDistributionPoint true to add the CRL distribution point of the local server
     * @return the certificate
     * @throws Exception in case of error
     */
    private X509Certificate createLeaf(BigInteger serial, boolean withCrlDistributionPoint) throws Exception {
        KeyPair keyPair = createKeyPair();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(caCertificate, serial, new Date(System.currentTimeMillis() - ONE_HOUR),
                new Date(System.currentTimeMillis() + ONE_DAY), new X500Name("CN=leaf" + serial), keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        if (withCrlDistributionPoint) {
            GeneralNames names = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl));
            DistributionPoint distributionPoint = new DistributionPoint(new DistributionPointName(names), null, null);
            builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] {distributionPoint}));
        }
        return new JcaX509CertificateConverter().getCertificate(builder.build(createSigner()));
    }


    /**
     * Create a CRL signed by the CA.
     *
     * @param revokedSerial the revoked serial number
     * @return the encoded CRL
     * @throws Exception in case of error
     */
    private byte[] createCrl(BigInteger revokedSerial) throws Exception {
        Date now = new Date();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(new X500Name(CA_DN), new Date(now.getTime() - ONE_HOUR));
        builder.setNextUpdate(new Date(now.getTime() + ONE_DAY));
        builder.addCRLEntry(revokedSerial, new Date(now.getTime() - ONE_HOUR), CRLReason.keyCompromise);
        return builder.build(createSigner()).getEncoded();
    }


    /**
     * Create a signer with the CA key.
     *
     * @return the signer
     * @throws Exception in case of error
     */
    private ContentSigner createSigner() throws Exception {
        return new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(caKeyPair.getPrivate());
    }


    /**
     * Create a RSA key pair.
     *
     * @return the key pair
     * @throws Exception in case of error
     */
    private KeyPair createKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
