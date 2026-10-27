/*
 * X509CertificateGenerator.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.impl;

import com.github.toolarium.security.certificate.ICertificateGenerator;
import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * X509 certificate generator. It uses the Bouncycastle lightweight API to generate X.509 certificates programmatically.
 * 
 * @author patrick
 */
public class CertificateGenerator implements ICertificateGenerator {
    private static final long ONE_DAY = 1000L * 60 * 60 * 24;
    private static final Logger LOG = LoggerFactory.getLogger(CertificateGenerator.class);
    private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();
    private static final SecureRandom SERIAL_RANDOM = new SecureRandom();
    private static final int SERIAL_NUMBER_BITS = 128;
    private final boolean allowNonCaParent;


    /**
     * Constructor for CertificateGenerator
     */
    public CertificateGenerator() {
        this(false);
    }


    /**
     * Constructor for CertificateGenerator
     *
     * @param allowNonCaParent true to allow a parent certificate which is no CA certificate (behaviour of version 1.1.8
     *     and older); the created chain is then rejected by a strict chain validation
     */
    public CertificateGenerator(boolean allowNonCaParent) {
        this.allowNonCaParent = allowNonCaParent;
    }



    /**
     * @see com.github.toolarium.security.certificate.ICertificateGenerator#createCACertificate(java.lang.String, int)
     */
    @Override
    public CertificateStore createCACertificate(String dn, int validityDays) throws GeneralSecurityException {
        return createCertificate(PKIUtil.getInstance().generateKeyPair(null, "RSA", 2048), null, dn, null, new Date() /* startDate */, validityDays, true);
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateGenerator#createCACertificate(java.security.KeyPair, com.github.toolarium.security.certificate.dto.CertificateStore, java.lang.String, java.util.Date, int)
     */
    @Override
    public CertificateStore createCACertificate(KeyPair keyPair, CertificateStore parent, String dn, Date startDate, int validityDays) throws GeneralSecurityException {
        return createCertificate(keyPair, parent, dn, null, startDate, validityDays, true);
    }

    /**
     * @see com.github.toolarium.security.certificate.ICertificateGenerator#createCreateCertificate(com.github.toolarium.security.certificate.dto.CertificateStore, java.lang.String, java.lang.String, java.util.Date, int)
     */
    @Override
    public CertificateStore createCreateCertificate(CertificateStore certificateStore, String dn, final String alternativeDn, Date startDate, int validityDays) throws GeneralSecurityException {
        return createCreateCertificate(certificateStore.getKeyPair(), certificateStore, dn, alternativeDn, startDate, validityDays);
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateGenerator#createCreateCertificate(java.lang.String)
     */
    @Override
    public CertificateStore createCreateCertificate(String dn) throws GeneralSecurityException {
        return createCreateCertificate(PKIUtil.getInstance().generateKeyPair(null, "RSA", 2048), null, dn, null, new Date() /* startDate */,  1 * 365 /* 1 year: validityDays */);
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateGenerator#createCreateCertificate(java.lang.String, java.lang.String, int)
     */
    @Override
    public CertificateStore createCreateCertificate(String dn, final String alternativeDn, int validityDays) throws GeneralSecurityException {
        return createCreateCertificate(PKIUtil.getInstance().generateKeyPair(null, "RSA", 2048), null, dn, alternativeDn, new Date() /* startDate */,  validityDays);
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateGenerator#createCreateCertificate(java.security.KeyPair, java.lang.String, java.lang.String, java.util.Date, int)
     */
    @Override
    public CertificateStore createCreateCertificate(final KeyPair keyPair, String dn, final String alternativeDn, Date startDate, int validityDays) throws GeneralSecurityException {
        return createCreateCertificate(keyPair, null, dn, alternativeDn, startDate, validityDays);
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateGenerator#createCreateCertificate(java.security.KeyPair, com.github.toolarium.security.certificate.dto.CertificateStore, java.lang.String, java.lang.String, java.util.Date, int)
     */
    @Override
    public CertificateStore createCreateCertificate(final KeyPair keyPair, 
                                                    final CertificateStore parent, 
                                                    final String dn, 
                                                    final String alternativeDn,
                                                    final Date startDate, 
                                                    final int inputValidityDays) throws GeneralSecurityException {
        return createCertificate(keyPair, parent, dn, alternativeDn, startDate, inputValidityDays, false);
    }


    /**
     * Creates a certificate
     *
     * @param keyPair the key pair to create the certificate from
     * @param parent the parent certificate chain or null for a self-signed certificate
     * @param dn the name
     * @param alternativeDn alternative dn (e.g. hostname), only used for end-entity certificates
     * @param startDate the start date
     * @param inputValidityDays number of days (min 1 day)
     * @param isCa true to create a CA certificate (basic constraints CA, key usage keyCertSign and cRLSign); false
     *        to create an end-entity certificate (subject alternative names, server and client authentication)
     * @return a new created certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    private CertificateStore createCertificate(final KeyPair keyPair,
                                               final CertificateStore parent,
                                               final String dn,
                                               final String alternativeDn,
                                               final Date startDate,
                                               final int inputValidityDays,
                                               final boolean isCa) throws GeneralSecurityException {
        if (keyPair == null || keyPair.getPublic() == null) {
            throw new GeneralSecurityException("Invalid key pair (null)!");
        }
        if (dn == null) {
            throw new GeneralSecurityException("Invalid dn (null)!");
        }
        if (startDate == null) {
            throw new GeneralSecurityException("Invalid start date (null)!");
        }

        boolean hasParent = parent != null && parent.getCertificates() != null && parent.getCertificates().length > 0;
        if (hasParent) {
            verifyParent(parent);
        } else if (keyPair.getPrivate() == null) {
            throw new GeneralSecurityException("Invalid key pair, the private key to sign the self-signed certificate is missing!");
        }

        try {
            int validityDays = inputValidityDays;
            LocalDateTime maxDate;
            if (validityDays < 1) {
                throw new IllegalArgumentException("validityDays must be >= 1, got: " + validityDays);
            }

            if (validityDays % 365 == 0) {
                int years = validityDays / 365;
                maxDate = dateToLocalDateTime(startDate);
                maxDate = maxDate.plusYears(years);
            } else {
                maxDate = dateToLocalDateTime(new Date(startDate.getTime() + (ONE_DAY * (validityDays - 1))));
            }
            
            final BigInteger serial = new BigInteger(SERIAL_NUMBER_BITS, SERIAL_RANDOM).abs();
            //final X500Name name = new X500Name("CN=" + dn); // "CN=name, O=company, L=location, ST=state, C=country";
            final X500Name name = new X500NameBuilder(BCStyle.INSTANCE)
                        .addRDN(BCStyle.CN, dn)//.addRDN(BCStyle.O, company).addRDN(BCStyle.L, location).addRDN(BCStyle.ST, state).addRDN(BCStyle.C, country)
                        .build();
            
            final X500Name issuer;
            final PrivateKey privateKeySigner;
            if (parent == null || parent.getCertificates() == null || parent.getCertificates().length <= 0) {
                issuer = name;
                privateKeySigner = keyPair.getPrivate();
            } else {
                //PKIUtil.getInstance().logCertificate("Parent certificates:", parent.getCertificates());
                privateKeySigner = parent.getKeyPair().getPrivate();
                // preserve exact DER encoding from the parent cert's subject: byte-level match required by PKIX path validation
                issuer = X500Name.getInstance(ASN1Sequence.getInstance(parent.getCertificates()[0].getSubjectX500Principal().getEncoded()));
            }
            
            String dnName = alternativeDn;
            if (dnName == null) {
                dnName = dn;
            }
            final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded()));
            final Date notBeforedate = localDateTimeToDate(dateToLocalDateTime(startDate).with(LocalTime.MIN)); // start of the day
            final Date notAfter = localDateTimeToDate(maxDate.with(LocalTime.MAX)); // end of the day;
            // build SAN extension: localhost is only added if no alternative name (host name) is given
            GeneralName[] sanNames;
            if (alternativeDn != null || "localhost".equals(dnName)) {
                sanNames = new GeneralName[] {new GeneralName(GeneralName.dNSName, dnName)};
            } else {
                sanNames = new GeneralName[] {new GeneralName(GeneralName.dNSName, dnName), new GeneralName(GeneralName.dNSName, "localhost")};
            }
            final X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, serial, notBeforedate, notAfter, name, publicKeyInfo);
            if (!isCa) {
                // a CA certificate is not bound to a host name
                builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sanNames));
            }
            // add extensions

            boolean isSelfSigned = (parent == null || parent.getCertificates() == null || parent.getCertificates().length <= 0);
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            AuthorityKeyIdentifier authorityKeyIdentifier;
            if (isSelfSigned) {
                // self-signed: AKI references own public key
                authorityKeyIdentifier = extUtils.createAuthorityKeyIdentifier(keyPair.getPublic());
            } else {
                // CA-signed cert: AKI must reference the issuer's (CA's) public key
                authorityKeyIdentifier = extUtils.createAuthorityKeyIdentifier(parent.getCertificates()[0].getPublicKey());
            }
            builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
            builder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
            builder.addExtension(Extension.basicConstraints, isCa, new BasicConstraints(isCa));
            KeyUsage usage;
            if (isCa) {
                usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.cRLSign);
            } else {
                usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement);
            }
            builder.addExtension(Extension.keyUsage, true, usage.getEncoded());
            if (!isCa) {
                // a CA certificate must not be usable as server / client certificate
                ExtendedKeyUsage usageEx = new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection });
                boolean critical = true;
                builder.addExtension(Extension.extendedKeyUsage, !critical, usageEx.getEncoded());
            }
            
            // build certificate
            String signatureAlgorithm = "SHA256WithRSAEncryption";
            if ("RSA".equals(keyPair.getPublic().getAlgorithm())) {
                signatureAlgorithm = "SHA256WithRSA";
                //signatureAlgorithm = "SHA256WithRSAEncryption";
            } else if ("EC".equals(keyPair.getPublic().getAlgorithm())) {
                signatureAlgorithm = "SHA256withECDSA";
            } else if ("DSA".equals(keyPair.getPublic().getAlgorithm())) {
                signatureAlgorithm = "SHA256withDSA";
            }

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC_PROVIDER).build(privateKeySigner);
            X509CertificateHolder holder = builder.build(signer);
            // use the default JDK CertificateFactory (no BC provider) so the resulting X509Certificate
            // is a JDK-native instance, required for compatibility with the JDK's PKIX CertPathValidator.
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
            
            int size = 1;
            if (parent != null && parent.getCertificates() != null) {
                size += parent.getCertificates().length;
            }

            X509Certificate[] chain = new X509Certificate[size];
            chain[0] = cert;

            if (parent != null && parent.getCertificates() != null && parent.getCertificates().length > 0) {
                for (int i = parent.getCertificates().length - 1; i >= 0; i--) {
                    chain[i + 1] = parent.getCertificates()[i];
                }
                //chain[1] = parent.getCertificates()[parentChainLength - 1];
            }

            // check the signature of the new certificate only: the parent chain is not changed and the generator
            // must be able to create expired or not yet valid certificates
            if (hasParent) {
                cert.verify(parent.getCertificates()[0].getPublicKey());
            } else {
                cert.verify(keyPair.getPublic());
            }

            LOG.info("Created certificate '{}' (serial {}), issued by '{}', valid from {} to {}.",
                     cert.getSubjectX500Principal().getName(), cert.getSerialNumber(), cert.getIssuerX500Principal().getName(), cert.getNotBefore(), cert.getNotAfter());
            if (LOG.isDebugEnabled()) {
                PKIUtil.getInstance().processCertificate(LOG::debug, "Created certificate chain: " + chain.length + " certificate(s)...", chain);
            }
            return new CertificateStore(keyPair, chain);
        } catch (OperatorCreationException | IOException ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }

    

    /**
     * Verify that the parent can issue certificates: its certificate must be a CA (or a self-signed root of version 1),
     * unless a parent which is no CA is allowed, and its key pair must contain the private key.
     *
     * @param parent the parent certificate store with at least one certificate
     * @throws GeneralSecurityException if the parent can not issue certificates
     */
    private void verifyParent(final CertificateStore parent) throws GeneralSecurityException {
        X509Certificate parentCertificate = parent.getCertificates()[0];
        if (parentCertificate == null) {
            throw new GeneralSecurityException("Invalid parent certificate (null)!");
        }

        String parentSubject = parentCertificate.getSubjectX500Principal().getName();
        boolean isV1SelfSignedRoot = parentCertificate.getVersion() == 1 && parentCertificate.getSubjectX500Principal().equals(parentCertificate.getIssuerX500Principal());
        if (!allowNonCaParent && parentCertificate.getBasicConstraints() < 0 && !isV1SelfSignedRoot) {
            throw new GeneralSecurityException("Parent certificate '" + parentSubject + "' is not a CA certificate (basic constraints)!");
        }

        if (parent.getKeyPair() == null || parent.getKeyPair().getPrivate() == null) {
            throw new GeneralSecurityException("Parent certificate '" + parentSubject + "' has no private key to sign the certificate!");
        }
    }


    /**
     * Generate a self-signed certificate and write it to files.
     *
     * <p>Usage: CertificateGenerator &lt;password&gt; [alias] [dn] [alternativeDn] [filename] [validityDays]</p>
     *
     * <p>The test CA can e.g. be created with
     * echo -e"AT\nUpper Austria\nSteyr\nMy Organization\nNetwork tests\nTest CA certificate\nme@myserver.com\n\n\n"
     * | \ openssl req -new -x509 -outform PEM -newkey rsa:2048 -nodes -keyout
     * /tmp/ca.key -keyform PEM -out /tmp/ca.crt -days 365; echo "test password"
     * | openssl pkcs12 -export -in /tmp/ca.crt -inkey /tmp/ca.key -out ca.p12
     * -name "Test CA" -passout stdin The created certificate can be displayed
     * with openssl pkcs12 -nodes -info -in test.p12 &gt; /tmp/test.cert &amp;&amp; openssl
     * x509 -noout -text -in /tmp/test.cert</p>
     *
     * @param args the arguments: password (required), alias, dn, alternativeDn, filename, validityDays
     * @throws Exception in case of error
     */
    public static void main(String[] args) throws Exception {
        if (args == null || args.length < 1) {
            LOG.info("Usage: CertificateGenerator [alias] [dn] [alternativeDn] [filename] [validityDays]");
            return;
        }

        String dn = "Test CN";
        if (args.length > 1) {
            dn = args[1];
        }

        String alternativeDn = "localhost";
        if (args.length > 2) {
            alternativeDn = args[2];
        }

        String fileName = "testca";
        if (args.length > 3) {
            fileName = args[3];
        }

        int validityDays = 365;
        if (args.length > 4) {
            validityDays = Integer.parseInt(args[4]);
        }

        // Read password from console (no echo) or stdin, never from a command-line argument,
        // which would expose it in process listings and shell history.
        final char[] password;
        java.io.Console console = System.console();
        if (console != null) {
            password = console.readPassword("Keystore password: ");
        } else {
            String line;
            try (java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(System.in))) {
                line = br.readLine();
            }
            if (line != null) {
                password = line.toCharArray();
            } else {
                password = new char[0];
            }
        }

        String alias = args[0];
        CertificateGenerator g = new CertificateGenerator();
        CertificateStore certificateStore = g.createCreateCertificate(PKIUtil.getInstance().generateKeyPair(null, "RSA", 2048),
                                                                      dn,
                                                                      alternativeDn,
                                                                      new Date(),
                                                                      validityDays);
        certificateStore.write(fileName, alias, password);
        java.util.Arrays.fill(password, '\0');
        certificateStore.writeCertificate(fileName);
        certificateStore.writePublicKey(fileName);
        certificateStore.writePrivateKey(fileName);
    }


    /**
     * Convert {@link Date} to {@link LocalDateTime}.
     *
     * @param date the {@link Date}
     * @return the {@link LocalDateTime}.
     */
    private LocalDateTime dateToLocalDateTime(Date date) {
        return LocalDateTime.ofInstant(date.toInstant(), ZoneOffset.UTC);
    }

    
    /**
     * Convert {@link LocalDateTime} to {@link Date}.
     *
     * @param localDateTime the {@link LocalDateTime}.
     * @return the {@link Date}.
     */
    private Date localDateTimeToDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneOffset.UTC).toInstant());
    }
}
