/*
 * CertificateFindingsTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.certificate.impl.CertificateVerifier;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


/**
 * Test the fixes of the certificate findings: empty chain, path length and name constraints, issuer and subject
 * names, symbolic links, parent certificate store, null input and exception messages.
 *
 * @author patrick
 */
public class CertificateFindingsTest {
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String ROOT_DN = "CN=Findings Root CA";
    private static final String INTERMEDIATE_DN = "CN=Findings Intermediate CA";
    private static final String SUB_CA_DN = "CN=Findings Sub CA";
    private static final String LEAF_DN = "CN=Findings Leaf";
    private static final String OTHER_LEAF_DN = "CN=Findings Other Leaf";
    private static final String OTHER_DN = "CN=Findings Other CA";
    private static final String HOST = "localhost";
    private static final String RSA = "RSA";
    private static final int KEY_SIZE = 2048;
    private static final int VALIDITY_DAYS = 365;
    private static final long ONE_HOUR = 60L * 60L * 1000L;
    private static final long ONE_DAY = 24L * ONE_HOUR;
    private KeyPair rootKeyPair;
    private KeyPair intermediateKeyPair;
    private KeyPair subCaKeyPair;
    private KeyPair leafKeyPair;
    private long serial;


    /**
     * Constructor for CertificateFindingsTest
     */
    public CertificateFindingsTest() {
        // NOP
    }


    /**
     * Create the key pairs.
     *
     * @throws Exception in case of error
     */
    @BeforeEach
    public void setUp() throws Exception {
        rootKeyPair = createKeyPair();
        intermediateKeyPair = createKeyPair();
        subCaKeyPair = createKeyPair();
        leafKeyPair = createKeyPair();
    }


    /**
     * N36: an intermediate CA with path length 0 must not issue a sub CA, but it may issue a leaf.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testPathLengthConstraint() throws Exception {
        X509Certificate root = createCertificate(ROOT_DN, ROOT_DN, rootKeyPair.getPublic(), rootKeyPair.getPrivate(), new BasicConstraints(true), false);
        X509Certificate intermediate = createCertificate(INTERMEDIATE_DN, ROOT_DN, intermediateKeyPair.getPublic(), rootKeyPair.getPrivate(), new BasicConstraints(0), false);
        X509Certificate subCa = createCertificate(SUB_CA_DN, INTERMEDIATE_DN, subCaKeyPair.getPublic(), intermediateKeyPair.getPrivate(), new BasicConstraints(true), false);
        X509Certificate leaf = createCertificate(LEAF_DN, SUB_CA_DN, leafKeyPair.getPublic(), subCaKeyPair.getPrivate(), new BasicConstraints(false), false);
        CertificateVerifier verifier = new CertificateVerifier();
        assertThrows(CertificateException.class, () -> verifier.verifyCertificateChain(null, new X509Certificate[] {leaf, subCa, intermediate, root}));

        X509Certificate directLeaf = createCertificate(LEAF_DN, INTERMEDIATE_DN, leafKeyPair.getPublic(), intermediateKeyPair.getPrivate(), new BasicConstraints(false), false);
        assertDoesNotThrow(() -> verifier.verifyCertificateChain(null, new X509Certificate[] {directLeaf, intermediate, root}));
    }


    /**
     * N36: an issuer with critical name constraints is rejected, because they are not enforced.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testCriticalNameConstraintsAreRejected() throws Exception {
        X509Certificate root = createCertificate(ROOT_DN, ROOT_DN, rootKeyPair.getPublic(), rootKeyPair.getPrivate(), new BasicConstraints(true), true);
        X509Certificate leaf = createCertificate(LEAF_DN, ROOT_DN, leafKeyPair.getPublic(), rootKeyPair.getPrivate(), new BasicConstraints(false), false);
        assertThrows(CertificateException.class, () -> new CertificateVerifier().verifyCertificateChain(null, new X509Certificate[] {leaf, root}));
    }


    /**
     * N37: a certificate whose issuer does not match the subject of the next certificate is rejected, also without strict validation.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testIssuerSubjectMismatchIsRejected() throws Exception {
        X509Certificate root = createCertificate(ROOT_DN, ROOT_DN, rootKeyPair.getPublic(), rootKeyPair.getPrivate(), new BasicConstraints(true), false);
        // signed by the root key, but with an other issuer name
        X509Certificate leaf = createCertificate(LEAF_DN, OTHER_DN, leafKeyPair.getPublic(), rootKeyPair.getPrivate(), new BasicConstraints(false), false);
        CertificateVerifier verifier = new CertificateVerifier();
        assertThrows(CertificateException.class, () -> verifier.verifyCertificateChain(null, new X509Certificate[] {leaf, root}));

        verifier.setStrictChainValidation(false);
        assertThrows(CertificateException.class, () -> verifier.verifyCertificateChain(null, new X509Certificate[] {leaf, root}));
    }


    /**
     * N59: writing to a symbolic link is refused and the link target is not changed.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testWriteRefusesSymbolicLink() throws Exception {
        Path dir = Files.createTempDirectory("certificate-findings");
        Path target = dir.resolve("target.txt");
        Path link = dir.resolve("link.crt");
        try {
            Files.write(target, "original".getBytes(StandardCharsets.UTF_8));
            boolean isLinkCreated;
            try {
                Files.createSymbolicLink(link, target);
                isLinkCreated = true;
            } catch (IOException | UnsupportedOperationException | SecurityException e) {
                // e.g. on Windows without the privilege to create symbolic links
                isLinkCreated = false;
            }
            Assumptions.assumeTrue(isLinkCreated, "Symbolic links can not be created on this system.");

            CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(HOST);
            assertThrows(IOException.class, () -> certificateStore.writeCertificate(link.toString()));
            assertEquals("original", new String(Files.readAllBytes(target), StandardCharsets.UTF_8));
        } finally {
            Files.deleteIfExists(link);
            Files.deleteIfExists(target);
            Files.deleteIfExists(dir);
        }
    }


    /**
     * N60: the parent must be a CA certificate with a private key.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testParentMustBeCaWithPrivateKey() throws Exception {
        ICertificateGenerator generator = CertificateUtilFactory.getInstance().getGenerator();
        CertificateStore endEntityParent = generator.createCreateCertificate(HOST);
        assertThrows(GeneralSecurityException.class,
                     () -> generator.createCreateCertificate(leafKeyPair, endEntityParent, LEAF_DN, HOST, new Date(), VALIDITY_DAYS));

        CertificateStore ca = generator.createCACertificate(ROOT_DN, VALIDITY_DAYS);
        CertificateStore caWithoutKey = new CertificateStore((KeyPair) null, ca.getCertificates());
        assertThrows(GeneralSecurityException.class,
                     () -> generator.createCreateCertificate(leafKeyPair, caWithoutKey, LEAF_DN, HOST, new Date(), VALIDITY_DAYS));

        CertificateStore leaf = generator.createCreateCertificate(leafKeyPair, ca, LEAF_DN, HOST, new Date(), VALIDITY_DAYS);
        assertEquals(2, leaf.getCertificates().length);

        // a generator which allows a parent which is no CA (behaviour of version 1.1.8 and older)
        ICertificateGenerator allowNonCaParentGenerator = CertificateUtilFactory.getInstance().getGenerator(true);
        CertificateStore leafOfEndEntity = allowNonCaParentGenerator.createCreateCertificate(leafKeyPair, endEntityParent, LEAF_DN, HOST, new Date(), VALIDITY_DAYS);
        assertEquals(2, leafOfEndEntity.getCertificates().length);
        assertThrows(GeneralSecurityException.class,
                     () -> allowNonCaParentGenerator.createCreateCertificate(leafKeyPair, caWithoutKey, LEAF_DN, HOST, new Date(), VALIDITY_DAYS));
        assertThrows(GeneralSecurityException.class,
                     () -> CertificateUtilFactory.getInstance().getGenerator(false).createCreateCertificate(leafKeyPair, endEntityParent, LEAF_DN, HOST, new Date(), VALIDITY_DAYS));
    }


    /**
     * N61: null input is rejected with a security exception instead of a NullPointerException.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testNullInput() throws Exception {
        ICertificateGenerator generator = CertificateUtilFactory.getInstance().getGenerator();
        assertThrows(GeneralSecurityException.class, () -> generator.createCreateCertificate((KeyPair) null, LEAF_DN, HOST, new Date(), VALIDITY_DAYS));
        assertThrows(GeneralSecurityException.class, () -> generator.createCreateCertificate(leafKeyPair, (String) null, HOST, new Date(), VALIDITY_DAYS));
        assertThrows(GeneralSecurityException.class, () -> generator.createCreateCertificate(leafKeyPair, LEAF_DN, HOST, null, VALIDITY_DAYS));

        X509Certificate root = createCertificate(ROOT_DN, ROOT_DN, rootKeyPair.getPublic(), rootKeyPair.getPrivate(), new BasicConstraints(true), false);
        CertificateVerifier verifier = new CertificateVerifier();
        assertThrows(CertificateException.class, () -> verifier.verifyCertificateChain(null, new X509Certificate[] {null, root}));
        assertThrows(CertificateException.class, () -> verifier.verifyCertificate(null, null, root));
    }


    /**
     * N57: localhost is only added as subject alternative name if no alternative name (host name) is given.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testLocalhostOnlyWithoutAlternativeName() throws Exception {
        X509Certificate withHost = CertificateUtilFactory.getInstance().getGenerator()
                .createCreateCertificate(leafKeyPair, LEAF_DN, "api.example.com", new Date(), VALIDITY_DAYS).getCertificates()[0];
        assertEquals(1, withHost.getSubjectAlternativeNames().size());
        assertEquals("api.example.com", withHost.getSubjectAlternativeNames().iterator().next().get(1));

        X509Certificate withoutHost = CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate("myname").getCertificates()[0];
        assertEquals(2, withoutHost.getSubjectAlternativeNames().size());
        boolean hasLocalhost = false;
        for (java.util.List<?> entry : withoutHost.getSubjectAlternativeNames()) {
            if ("localhost".equals(entry.get(1))) {
                hasLocalhost = true;
            }
        }
        assertTrue(hasLocalhost);
    }


    /**
     * N67: the certificate chain of a certificate store can not be changed from outside.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testCertificateStoreChainIsCopied() throws Exception {
        CertificateStore ca = CertificateUtilFactory.getInstance().getGenerator().createCACertificate(ROOT_DN, VALIDITY_DAYS);
        X509Certificate caCertificate = ca.getCertificates()[0];
        X509Certificate otherCertificate = CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(HOST).getCertificates()[0];

        X509Certificate[] chain = new X509Certificate[] {caCertificate};
        CertificateStore store = new CertificateStore(ca.getKeyPair(), chain);
        chain[0] = otherCertificate;
        assertEquals(caCertificate, store.getCertificates()[0]);

        store.getCertificates()[0] = otherCertificate;
        assertEquals(caCertificate, store.getCertificates()[0]);
    }


    /**
     * N62: the exception message of an invalid chain contains only the subject names, not the certificate dump.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testChainExceptionMessage() throws Exception {
        X509Certificate leaf = createCertificate(LEAF_DN, ROOT_DN, leafKeyPair.getPublic(), rootKeyPair.getPrivate(), new BasicConstraints(false), false);
        X509Certificate otherLeaf = createCertificate(OTHER_LEAF_DN, ROOT_DN, subCaKeyPair.getPublic(), rootKeyPair.getPrivate(), new BasicConstraints(false), false);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                                                  () -> CertificateUtilFactory.getInstance().geChainAnalyzer().toRootFirst(Arrays.asList(leaf, otherLeaf)));
        assertTrue(e.getMessage().contains(LEAF_DN));
        assertTrue(e.getMessage().contains(OTHER_LEAF_DN));
        assertFalse(e.getMessage().contains("Signature Algorithm"));
    }


    /**
     * Create a certificate.
     *
     * @param subjectDn the subject name
     * @param issuerDn the issuer name
     * @param subjectKey the public key of the subject
     * @param signerKey the private key of the signer
     * @param basicConstraints the basic constraints
     * @param addNameConstraints true to add critical name constraints
     * @return the certificate
     * @throws Exception in case of error
     */
    private X509Certificate createCertificate(String subjectDn, String issuerDn, PublicKey subjectKey, PrivateKey signerKey, BasicConstraints basicConstraints, boolean addNameConstraints) throws Exception {
        long now = System.currentTimeMillis();
        serial++;
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(issuerDn), BigInteger.valueOf(serial), new Date(now - ONE_HOUR),
                new Date(now + ONE_DAY), new X500Name(subjectDn), subjectKey);
        builder.addExtension(Extension.basicConstraints, true, basicConstraints);
        if (basicConstraints.isCA()) {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }
        if (addNameConstraints) {
            GeneralSubtree[] permitted = new GeneralSubtree[] {new GeneralSubtree(new GeneralName(GeneralName.dNSName, "example.com"))};
            builder.addExtension(Extension.nameConstraints, true, new NameConstraints(permitted, null));
        }
        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(signerKey)));
    }


    /**
     * Create a RSA key pair.
     *
     * @return the key pair
     * @throws Exception in case of error
     */
    private KeyPair createKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
        generator.initialize(KEY_SIZE);
        return generator.generateKeyPair();
    }
}
