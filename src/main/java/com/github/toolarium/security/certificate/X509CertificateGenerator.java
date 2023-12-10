/*
 * X509CertificateGenerator.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.certificate.util.PKIUtil;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;
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
public final class X509CertificateGenerator {
    private static final long ONE_DAY = 1000L * 60 * 60 * 24;
    private static final Logger LOG = LoggerFactory.getLogger(X509CertificateGenerator.class);

    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final X509CertificateGenerator INSTANCE = new X509CertificateGenerator();
    }

    
    /**
     * Constructor for X509CertificateGenerator
     */
    private X509CertificateGenerator() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static X509CertificateGenerator getInstance() {
        return HOLDER.INSTANCE;
    }


    /**
     * Creates a certificate
     * 
     * @param certificateStore the certificate store
     * @param dn the name
     * @param alternativeDn the alternative dn
     * @param startDate the start date
     * @param validityDays number of days
     * @return a new created certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    public CertificateStore createCreateCertificate(CertificateStore certificateStore, String dn, final String alternativeDn, Date startDate, int validityDays) throws GeneralSecurityException {
        return createCreateCertificate(certificateStore.getKeyPair(), certificateStore, dn, alternativeDn, startDate, validityDays);
    }

    
    /**
     * Creates a self signed certificate
     * 
     * @param dn the name
     * @return a new created certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    public CertificateStore createCreateCertificate(String dn) throws GeneralSecurityException {
        return createCreateCertificate(PKIUtil.getInstance().generateKeyPair("RSA", 2048), null, dn, null, new Date() /* startDate */,  1 * 365 /* 1 year: validityDays */);
    }

    
    /**
     * Creates a certificate
     * 
     * @param dn the name
     * @param alternativeDn the alternative dn
     * @param validityDays number of days
     * @return a new created certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    public CertificateStore createCreateCertificate(String dn, final String alternativeDn, int validityDays) throws GeneralSecurityException {
        return createCreateCertificate(PKIUtil.getInstance().generateKeyPair("RSA", 2048), null, dn, alternativeDn, new Date() /* startDate */,  validityDays);
    }

    
    /**
     * Creates a certificate
     * 
     * @param keyPair the key pair to create the certificate from 
     * @param dn the name
     * @param alternativeDn the alternative dn
     * @param startDate the start date
     * @param validityDays number of days
     * @return a new created certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    public CertificateStore createCreateCertificate(final KeyPair keyPair, String dn, final String alternativeDn, Date startDate, int validityDays) throws GeneralSecurityException {
        return createCreateCertificate(keyPair, null, dn, alternativeDn, startDate, validityDays);
    }

    
    /**
     * Creates a certificate
     * 
     * @param keyPair the key pair to create the certificate from
     * @param parent the parent certificate chain 
     * @param dn the name
     * @param alternativeDn alternative dn (e.g. hostname)
     * @param startDate the start date
     * @param inputValidityDays number of days (min 1 day)
     * @return a new created certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    public CertificateStore createCreateCertificate(final KeyPair keyPair, 
                                                    final CertificateStore parent, 
                                                    final String dn, 
                                                    final String alternativeDn,
                                                    final Date startDate, 
                                                    final int inputValidityDays) throws GeneralSecurityException {
        try {
            int validityDays = inputValidityDays;
            LocalDateTime maxDate;
            if (validityDays < 1) {
                validityDays = 1; 
            }

            if (validityDays % 365 == 0) {
                int years = validityDays / 365;
                maxDate = dateToLocalDateTime(startDate);
                maxDate = maxDate.plusYears(years);
            } else {
                maxDate = dateToLocalDateTime(new Date(startDate.getTime() + (ONE_DAY * (validityDays - 1))));
            }
            
            final BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
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
                issuer = new X500Name(parent.getCertificates()[0].getIssuerX500Principal().getName());
            }
            
            String dnName = alternativeDn;
            if (dnName == null) {
                dnName = dn;
            }
            final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded()));
            final Date notBeforedate = localDateTimeToDate(dateToLocalDateTime(startDate).with(LocalTime.MIN)); // start of the day
            final Date notAfter = localDateTimeToDate(maxDate.with(LocalTime.MAX)); // end of the day;
            final X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, serial, notBeforedate, notAfter, name, publicKeyInfo)
                                                            .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.dNSName, dnName)));
            // add extensions

            boolean isCa = true; // ??
            boolean critical = true; // ?
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            AuthorityKeyIdentifier authorityKeyIdentifier = extUtils.createAuthorityKeyIdentifier(keyPair.getPublic());
            builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
            builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
            builder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
            builder.addExtension(Extension.basicConstraints, isCa, new BasicConstraints(isCa));
            KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.cRLSign | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment | KeyUsage.keyAgreement);
            builder.addExtension(Extension.keyUsage, false, usage.getEncoded());
            ExtendedKeyUsage usageEx = new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection });
            builder.addExtension(Extension.extendedKeyUsage, !critical, usageEx.getEncoded());
            
            // build certificate
            String signatureAlgorithm = "SHA256WithRSAEncryption";
            if ("RSA".equals(keyPair.getPublic().getAlgorithm())) {
                signatureAlgorithm = "SHA256WithRSA";
                //signatureAlgorithm = "SHA256WithRSAEncryption";
            } else if ("EC".equals(keyPair.getPublic().getAlgorithm())) {
                signatureAlgorithm = "SHA256withECRSA"; //"SHA256withECDSA"
            }

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(new BouncyCastleProvider()).build(privateKeySigner);
            X509CertificateHolder holder = builder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
            
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

            PKIUtil.getInstance().verifyCertificateChain(LOG::info, chain);
            return new CertificateStore(keyPair, chain);
        } catch (OperatorCreationException | GeneralSecurityException | IOException ex) {
            GeneralSecurityException e = new GeneralSecurityException(ex.getMessage());
            e.setStackTrace(ex.getStackTrace());
            throw e;
        }
    }

    

    /**
     * The test CA can e.g. be created with 
     * echo -e"AT\nUpper Austria\nSteyr\nMy Organization\nNetwork tests\nTest CA certificate\nme@myserver.com\n\n\n"
     * | \ openssl req -new -x509 -outform PEM -newkey rsa:2048 -nodes -keyout
     * /tmp/ca.key -keyform PEM -out /tmp/ca.crt -days 365; echo "test password"
     * | openssl pkcs12 -export -in /tmp/ca.crt -inkey /tmp/ca.key -out ca.p12
     * -name "Test CA" -passout stdin The created certificate can be displayed
     * with openssl pkcs12 -nodes -info -in test.p12 &gt; /tmp/test.cert &aml;&aml; openssl
     * x509 -noout -text -in /tmp/test.cert
     * @param args the arguments
     * @throws Exception in case of error
     */
    public static void main(String[] args) throws Exception {
        String fileName = "testca";
        X509CertificateGenerator g = new X509CertificateGenerator();
        CertificateStore certificateStore = g.createCreateCertificate(PKIUtil.getInstance().generateKeyPair("RSA", 2048), 
                                                                      "Test CN", 
                                                                      "localhost", 
                                                                      new Date(), 
                                                                      365);
        certificateStore.write(fileName, "alias", "4321");
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
        return LocalDateTime.ofInstant(date.toInstant(), ZoneId.systemDefault());
    }

    
    /**
     * Convert {@link LocalDateTime} to {@link Date}.
     *
     * @param localDateTime the {@link LocalDateTime}.
     * @return the {@link Date}.
     */
    private Date localDateTimeToDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }
}
