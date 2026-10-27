/*
 * CertificateChainValidationTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.certificate.impl.CertificateVerifier;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


/**
 * Test the strict chain validation of the {@link CertificateVerifier}: validity dates, basic constraints and key usage.
 *
 * @author patrick
 */
public class CertificateChainValidationTest {
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String CA_DN = "CN=Test Chain CA";
    private static final String LEAF_DN = "CN=leaf";
    private static final long ONE_HOUR = 60L * 60L * 1000L;
    private static final long ONE_DAY = 24L * ONE_HOUR;
    private KeyPair caKeyPair;
    private KeyPair leafKeyPair;


    /**
     * Constructor for CertificateChainValidationTest
     */
    public CertificateChainValidationTest() {
        // NOP
    }


    /**
     * Create the key pairs.
     *
     * @throws Exception in case of error
     */
    @BeforeEach
    public void setUp() throws Exception {
        caKeyPair = createKeyPair();
        leafKeyPair = createKeyPair();
    }


    /**
     * A valid chain is accepted.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testValidChain() throws Exception {
        X509Certificate ca = createCa(true, KeyUsage.keyCertSign | KeyUsage.cRLSign);
        X509Certificate leaf = createLeaf(ca, -ONE_HOUR, ONE_DAY);
        assertDoesNotThrow(() -> new CertificateVerifier().verifyCertificateChain(null, new X509Certificate[] {leaf, ca}));
    }


    /**
     * An expired certificate is rejected by default and accepted without strict chain validation.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testExpiredCertificate() throws Exception {
        X509Certificate ca = createCa(true, KeyUsage.keyCertSign);
        X509Certificate leaf = createLeaf(ca, -2 * ONE_DAY, -ONE_DAY);

        CertificateVerifier verifier = new CertificateVerifier();
        assertTrue(verifier.isStrictChainValidation());
        assertThrows(CertificateExpiredException.class, () -> verifier.verifyCertificateChain(null, new X509Certificate[] {leaf, ca}));

        verifier.setStrictChainValidation(false);
        assertDoesNotThrow(() -> verifier.verifyCertificateChain(null, new X509Certificate[] {leaf, ca}));
    }


    /**
     * An issuer which is not a CA is rejected.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testIssuerNotCa() throws Exception {
        X509Certificate ca = createCa(false, KeyUsage.keyCertSign);
        X509Certificate leaf = createLeaf(ca, -ONE_HOUR, ONE_DAY);
        assertThrows(CertificateException.class, () -> new CertificateVerifier().verifyCertificateChain(null, new X509Certificate[] {leaf, ca}));
    }


    /**
     * An issuer whose key usage does not allow to sign certificates is rejected.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testIssuerWithoutKeyCertSign() throws Exception {
        X509Certificate ca = createCa(true, KeyUsage.digitalSignature);
        X509Certificate leaf = createLeaf(ca, -ONE_HOUR, ONE_DAY);
        assertThrows(CertificateException.class, () -> new CertificateVerifier().verifyCertificateChain(null, new X509Certificate[] {leaf, ca}));
    }


    /**
     * Create a self-signed CA certificate.
     *
     * @param isCa the basic constraints CA flag
     * @param keyUsage the key usage
     * @return the certificate
     * @throws Exception in case of error
     */
    private X509Certificate createCa(boolean isCa, int keyUsage) throws Exception {
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(CA_DN), BigInteger.ONE, new Date(now - ONE_HOUR),
                new Date(now + ONE_DAY), new X500Name(CA_DN), caKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(caKeyPair.getPrivate())));
    }


    /**
     * Create a leaf certificate signed by the CA.
     *
     * @param ca the CA certificate
     * @param notBeforeOffset the not before offset from now in milliseconds
     * @param notAfterOffset the not after offset from now in milliseconds
     * @return the certificate
     * @throws Exception in case of error
     */
    private X509Certificate createLeaf(X509Certificate ca, long notBeforeOffset, long notAfterOffset) throws Exception {
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(ca, BigInteger.TWO, new Date(now + notBeforeOffset),
                new Date(now + notAfterOffset), new X500Name(LEAF_DN), leafKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(caKeyPair.getPrivate())));
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
