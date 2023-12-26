/*
 * PKIUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.util;

import com.github.toolarium.common.ByteArray;
import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.certificate.impl.CertificateConverter;
import com.github.toolarium.security.pki.KeyConverterFactory;
import com.github.toolarium.security.pki.impl.DSAKeyConverter;
import com.github.toolarium.security.pki.impl.ECKeyConverter;
import com.github.toolarium.security.pki.impl.RSAKeyConverter;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.function.Consumer;


/**
 * This class implements some handy methods in context of PKI
 * 
 * @author patrick
 */
@Deprecated
public final class PKIUtil {

    /** the public key certificate start */
    public static final String PUBLIC_CERTIFICATE_START = CertificateConverter.PUBLIC_CERTIFICATE_START;

    /** the public key certificate end */
    public static final String PUBLIC_CERTIFICATE_END = CertificateConverter.PUBLIC_CERTIFICATE_END;

    /** the public RSA key start */
    public static final String PUBLIC_RSA_KEY_START = RSAKeyConverter.PRIVATE_RSA_KEY_START;

    /** the public RSA key end */
    public static final String PUBLIC_RSA_KEY_END = RSAKeyConverter.PRIVATE_RSA_KEY_END;

    /** the public DSA key start */
    public static final String PUBLIC_DSA_KEY_START = DSAKeyConverter.PRIVATE_DSA_KEY_START;

    /** the public DSA key end */
    public static final String PUBLIC_DSA_KEY_END = DSAKeyConverter.PRIVATE_DSA_KEY_END;

    /** the public EC key start */
    public static final String PUBLIC_EC_KEY_START = ECKeyConverter.PRIVATE_EC_KEY_START;

    /** the public EC key end */
    public static final String PUBLIC_EC_KEY_END = ECKeyConverter.PRIVATE_EC_KEY_END;

    /** the private RSA key certificate start */
    public static final String PRIVATE_RSA_KEY_START = RSAKeyConverter.PRIVATE_RSA_KEY_START;

    /** the private RSA key certificate end */
    public static final String PRIVATE_RSA_KEY_END = RSAKeyConverter.PRIVATE_RSA_KEY_END;

    /** the private DSA key certificate start */
    public static final String PRIVATE_DSA_KEY_START = DSAKeyConverter.PRIVATE_DSA_KEY_START;

    /** the private DSA key certificate end */
    public static final String PRIVATE_DSA_KEY_END = DSAKeyConverter.PRIVATE_DSA_KEY_END;

    /** the private ECA key certificate start */
    public static final String PRIVATE_EC_KEY_START = ECKeyConverter.PRIVATE_EC_KEY_START;

    /** the private EC key certificate end */
    public static final String PRIVATE_EC_KEY_END = ECKeyConverter.PRIVATE_EC_KEY_END;


    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final PKIUtil INSTANCE = new PKIUtil();
    }

    
    /**
     * Constructor
     */
    private PKIUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static PKIUtil getInstance() {
        return HOLDER.INSTANCE;
    }
   
    
    /**
     * Generates a KeyPair containing a Private- and PublicKey
     * 
     * @return the created KeyPair
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public KeyPair generateKeyPair() throws GeneralSecurityException {
        return generateKeyPair(null, KeyConverterFactory.Types.RSA.name(), 2048);
    }

    
    /**
     * Generates a KeyPair containing a Private- and PublicKey
     * 
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param keySize the size of the key
     * @return the created KeyPair
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public KeyPair generateKeyPair(String algorithm, int keySize) throws GeneralSecurityException {
        return generateKeyPair(null, algorithm, keySize);
    }

    
    /**
     * Generates a KeyPair containing a Private- and PublicKey
     * 
     * @param provider the provider
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param k the size of the key
     * @return the created KeyPair
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public KeyPair generateKeyPair(String provider, String algorithm, int k) throws GeneralSecurityException {
        return com.github.toolarium.security.pki.util.PKIUtil.getInstance().generateKeyPair(provider, algorithm, k);
    }


    
    /**
     * Reads PKCS#8 formated public key from a buffer which are each bounded at the beginning by
     * <code>-----BEGIN PUBLIC KEY-----</code>, and bounded at the end by <code>-----END PUBLIC KEY-----</code>.
     * 
     * @param buffer the data
     * @return the public key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public PublicKey getDSAPublicKey(byte[] buffer) throws IOException, GeneralSecurityException {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.DSA).getPublicKey(buffer);
    }

    
    /**
     * Reads PKCS#8 formated public key from a buffer which are each bounded at the beginning by
     * <code>-----BEGIN PUBLIC KEY-----</code>, and bounded at the end by
     * <code>-----END PUBLIC KEY-----</code>.
     * 
     * @param buffer the data
     * @return the public key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public PublicKey getDSAPublicKey(ByteArray buffer) throws IOException, GeneralSecurityException {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.DSA).getPublicKey(buffer.toString());
    }


    /**
     * Reads PKCS#8 formated public key from a buffer, which are each bounded at the beginning by
     * <code>-----BEGIN RSA PRIVATE KEY-----</code>, and bounded at the end by
     * <code>-----END RSA PRIVATE KEY-----</code>.
     * @param buffer the data
     * @return the public key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public PublicKey getRSAPublicKey(byte[] buffer) throws IOException, GeneralSecurityException {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).getPublicKey(buffer);
    }

    
    /**
     * Reads PKCS#8 formated public key from a buffer which are each bounded at the beginning by
     * <code>-----BEGIN PUBLIC KEY-----</code>, and bounded at the end by
     * <code>-----END PUBLIC KEY-----</code>.
     * 
     * @param buffer the data
     * @return the public key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public PublicKey getRSAPublicKey(ByteArray buffer) throws IOException, GeneralSecurityException {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).getPublicKey(buffer.toString());
    }

    
    /**
     * Reads PKCS#8 formated public key from a buffer, which are each bounded at the beginning by
     * <code>-----BEGIN EC PUBLIC KEY-----</code>, and bounded at the end by
     * <code>-----END Ec PUBLIC KEY-----</code>.
     * @param buffer the data
     * @return the public key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public PublicKey getECPublicKey(byte[] buffer) throws IOException, GeneralSecurityException {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.EC).getPublicKey(buffer);
    }

    
    /**
     * Reads PKCS#8 formated public key from a buffer which are each bounded at the beginning by
     * <code>-----BEGIN PUBLIC KEY-----</code>, and bounded at the end by
     * <code>-----END PUBLIC KEY-----</code>.
     * 
     * @param buffer the data
     * @return the public key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public PublicKey getECPublicKey(ByteArray buffer) throws IOException, GeneralSecurityException {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.EC).getPublicKey(buffer.toString());
    }


    /**
     * Reads PKCS#8 formated DSA private key from a file, which are each bounded at the beginning by
     * <code>-----BEGIN DSA PRIVATE KEY-----</code>, and bounded at the end by
     * <code>-----END DSA PRIVATE KEY-----</code>.
     * 
     * @param fileName the file to read
     * @return the private key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public PrivateKey getDSAPrivateKey(String fileName) throws IOException, GeneralSecurityException {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.DSA).getPrivateKey(new File(fileName));
    }

    
    /**
     * Reads PKCS#8 formated DSA private key from a buffer, which are each bounded at the beginning by
     * <code>-----BEGIN DSA PRIVATE KEY-----</code>, and bounded at the end by
     * <code>-----END DSA PRIVATE KEY-----</code>.
     *
     * @param buffer the private key to encode
     * @return the private key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public PrivateKey getDSAPrivateKey(ByteArray buffer) throws IOException, GeneralSecurityException {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.DSA).getPrivateKey(buffer.toString());
    }


    /**
     * Reads PKCS#8 formated private key from a file, which are each bounded at the beginning by
     * <code>-----BEGIN RSA PRIVATE KEY-----</code>, and bounded at the end by
     * <code>-----END RSA PRIVATE KEY-----</code>.
     * 
     * @param fileName the file to read
     * @return the private key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public PrivateKey getRSAPrivateKey(String fileName) throws IOException, GeneralSecurityException {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).getPrivateKey(new File(fileName));
    }

    
    /**
     * Reads PKCS#8 formated RSA private key from a buffer,
     * which are each bounded at the beginning by
     * <code>-----BEGIN RSA PRIVATE KEY-----</code>, and bounded at the end by
     * <code>-----END RSA PRIVATE KEY-----</code>.
     *
     * @param buffer the private key to encode
     * @return the private key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public PrivateKey getRSAPrivateKey(ByteArray buffer) throws IOException, GeneralSecurityException {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).getPrivateKey(buffer.toString());
    }

    
    /**
     * Reads PKCS#8 formated private key from a file, which are each bounded at the beginning by
     * <code>-----BEGIN EC PRIVATE KEY-----</code>, and bounded at the end by
     * <code>-----END EC PRIVATE KEY-----</code>.
     * 
     * @param fileName the file to read
     * @return the private key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public PrivateKey getECPrivateKey(String fileName) throws IOException, GeneralSecurityException {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.EC).getPrivateKey(new File(fileName));
    }

    
    /**
     * Reads PKCS#8 formated EC private key from a buffer, which are each bounded at the beginning by
     * <code>-----BEGIN EC PRIVATE KEY-----</code>, and bounded at the end by
     * <code>-----END EC PRIVATE KEY-----</code>.
     *
     * @param buffer the private key to encode
     * @return the private key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public PrivateKey getECPrivateKey(ByteArray buffer) throws IOException, GeneralSecurityException {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.EC).getPrivateKey(buffer.toString());
    }


    /**
     * Formats a public key into a well formed private key, which
     * is bounded at the beginning and ending with the corresponding messages (see PKCS8).
     *
     * @param publicKey the public key
     * @return the well formed certificate
     */
    @Deprecated
    public String formatPublicKey(PublicKey publicKey) {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(publicKey).formatPublicKey(publicKey);
    }


    /**
     * Formats a public DSA key into a well formated X509 certificate (PEM format), which are each bounded at the beginning by
     * <code>-----BEGIN DSA PUBLIC KEY-----</code>, and bounded at the end by <code>-----END DSA PUBLIC KEY-----</code>.
     *
     * @param publicKey the public key to format
     * @return the well formed certificate
     */
    @Deprecated
    public String formatDSAPublicKey(PublicKey publicKey) {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(publicKey).formatPublicKey(publicKey);
    }

    
    /**
     * Formats a public RSA key into a well formated X509 certificate (PEM format), which are each bounded at the beginning by
     * <code>-----BEGIN RSA PUBLIC KEY-----</code>, and bounded at the end by <code>-----END RSA PUBLIC KEY-----</code>.
     *
     * @param publicKey the public key to format
     * @return the well formed certificate
     */
    @Deprecated
    public String formatRSAPublicKey(PublicKey publicKey) {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(publicKey).formatPublicKey(publicKey);
    }

    
    /**
     * Formats a public EC key into a well formated X509 certificate (PEM format), which are each bounded at the beginning by
     * <code>-----BEGIN EC PUBLIC KEY-----</code>, and bounded at the end by <code>-----END EC PUBLIC KEY-----</code>.
     *
     * @param publicKey the public key to format
     * @return the well formed certificate
     */
    @Deprecated
    public String formatECPublicKey(PublicKey publicKey) {
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(publicKey).formatPublicKey(publicKey);
    }

    
    /**
     * Formats a private key into a well formed private key, which
     * is bounded at the beginning and ending with the corresponding messages (see PKCS8).
     *
     * @param privateKey the private key
     * @return the well formed certificate
     */
    @Deprecated
    public String formatPrivateKey(PrivateKey privateKey) {
        if (privateKey == null) {
            return null;
        }
        
        return com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(privateKey).formatPrivateKey(privateKey);
    }

    
    /**
     * Formats a raw base64 encoded PKCS8 DSA to a well formed private key, which is bounded at the beginning by
     * <code>-----BEGIN DSA PRIVATE KEY-----</code>, and bounded at the end by <code>-----END DSA PRIVATE KEY-----</code>.
     *
     * @param rawData the raw data to format
     * @return the well formed certificate
     */
    @Deprecated
    public ByteArray formatDSAPKCS8(ByteArray rawData) {
        return new ByteArray(com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.DSA).formatPKCS8(rawData.toString()));
    }

    
    /**
     * Formats a raw base64 encoded PKCS8 RSA to a well formed private key, which is bounded at the beginning by
     * <code>-----BEGIN RSA PRIVATE KEY-----</code>, and bounded at the end by <code>-----END RSA PRIVATE KEY-----</code>.
     *
     * @param rawData the raw data to format
     * @return the well formed certificate
     */
    @Deprecated
    public ByteArray formatRSAPKCS8(ByteArray rawData) {
        return new ByteArray(com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).formatPKCS8(rawData.toString()));
    }

    
    /**
     * Formats a raw base64 encoded PKCS8 EC to a well formed private key, which is bounded at the beginning by
     * <code>-----BEGIN EC PRIVATE KEY-----</code>, and bounded at the end by <code>-----END EC PRIVATE KEY-----</code>.
     *
     * @param rawData the raw data to format
     * @return the well formed certificate
     */
    @Deprecated
    public ByteArray formatECPKCS8(ByteArray rawData) {
        return new ByteArray(com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.EC).formatPKCS8(rawData.toString()));
    }

    
    /**
     * Normalize a raw base64 encoded PKCS8 DSA to a well formed private key.
     *
     * @param rawData the raw data to normalize
     * @return the normalized private key
     */
    @Deprecated
    public ByteArray normalizeDSAPKCS8(ByteArray rawData) {
        return new ByteArray(com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.DSA).normalizePKCS8(rawData.toString()));
    }

    
    /**
     * Normalize a raw base64 encoded PKCS8 RSA to a well formed private key.
     *
     * @param rawData the raw data to normalize
     * @return the normalized private key
     */
    @Deprecated
    public ByteArray normalizeRSAPKCS8(ByteArray rawData) {
        return new ByteArray(com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.RSA).normalizePKCS8(rawData.toString()));
    }

    
    /**
     * Normalize a raw base64 encoded PKCS8 EC to a well formed private key.
     *
     * @param rawData the raw data to normalize
     * @return the normalized private key
     */
    @Deprecated
    public ByteArray normalizeECPKCS8(ByteArray rawData) {
        return new ByteArray(com.github.toolarium.security.pki.KeyConverterFactory.getInstance().getConverter(KeyConverterFactory.Types.EC).normalizePKCS8(rawData.toString()));
    }

    
    /**
     * Reas a PKCS#7 (with base64 encoded) X509 certificates from a file, which are each bounded at the beginning by
     * <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     *
     * @param fileName the file to read
     * @return the read certificates
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of error
     */
    @Deprecated
    public X509Certificate[] getX509Certificates(String fileName) throws GeneralSecurityException, IOException {
        return CertificateUtilFactory.getInstance().getConverter().getX509Certificates(new File(fileName));
    }


    /**
     * Reas a PKCS#7 (with base64 encoded) X509 certificates from the given buffer, which are each bounded at the beginning by
     * <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     *
     * @param inputData the data
     * @return the read certificates
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public X509Certificate[] getX509Certificates(ByteArray inputData) throws GeneralSecurityException {
        return CertificateUtilFactory.getInstance().getConverter().getX509Certificates(inputData.toString());
    }


    /**
     * Combine two certificate arrays
     *
     * @param certs the certificate
     * @param caCerts the ca certificate(s)
     * @return the combined certificates
     */
    @Deprecated
    public X509Certificate[] combineCertificates(X509Certificate[] certs, X509Certificate[] caCerts) {
        return CertificateUtilFactory.getInstance().getConverter().combineCertificates(certs, caCerts);
    }

    
    /**
     * Formats a raw base64 encoded X509 certificates to a well formated X509 certificate (PEM format), which are each bounded at the beginning by
     * <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     *
     * @param rawCertificate the raw certificate to format
     * @return the well formed certificate
     */
    @Deprecated
    public ByteArray formatPKCS7(ByteArray rawCertificate) {
        return new ByteArray(CertificateUtilFactory.getInstance().getConverter().formatPKCS7(rawCertificate.toString()).getBytes());
    }

    
    /**
     * Create certificate chain into a well formed string representation
     *
     * @param certificateChain the certificate chain
     * @return the string representation
     * @throws CertificateEncodingException In case of a certificate error
     */
    @Deprecated
    public String formatPKCS7(X509Certificate[] certificateChain) throws CertificateEncodingException {        
        return CertificateUtilFactory.getInstance().getConverter().formatPKCS7(certificateChain);
    }

    
    /**
     * Formats a certificate to a well formated X509 certificate (PEM format), which are each bounded at the beginning by
     * <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     *
     * @param certificate the certificate to format in PEM format
     * @return the well formed certificate
     * @throws CertificateEncodingException In case of a certificate error
     */
    @Deprecated
    public ByteArray formatPKCS7(Certificate certificate) throws CertificateEncodingException {
        return new ByteArray(CertificateUtilFactory.getInstance().getConverter().formatPKCS7(certificate).getBytes());
    }


    /**
     * Verifies a chain of certificates where the user certificate is stored at index 0. The self-signed top level certificate is verified using its inherent
     * public key. Any other certificate of the chain is verified by means of the public key derived from the issuing certificate which is located
     * one index higher in the chain.
     * certs[0] = user certificate.
     * certs[x] = self signed CA certificate
     *
     * @param consumer the consumer
     * @param certs the certificate chain to verify
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public void verifyCertificateChain(Consumer<String> consumer, X509Certificate[] certs) throws GeneralSecurityException {
        CertificateUtilFactory.getInstance().getVerifier().verifyCertificateChain(consumer, certs);
    }

    
    /**
     * Verifies the digital signature of a certificate.
     *
     * @param consumer the consumer
     * @param userCert the certificate to verify
     * @param caCert the certificate of the CA which has issued the userCert or <code>null</code> if the userCert is a self signed certificate
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public void verifyCertificate(Consumer<String> consumer, X509Certificate userCert, X509Certificate caCert) throws GeneralSecurityException {
        CertificateUtilFactory.getInstance().getVerifier().verifyCertificate(consumer, userCert, caCert);
    }


    /**
     * Verifies the digital signature of a certificate.
     *
     * @param consumer the consumer
     * @param userCertificate the certificate to verify
     * @throws GeneralSecurityException in case of error
     */
    @Deprecated
    public void verifyCertificate(Consumer<String> consumer, X509Certificate userCertificate) throws GeneralSecurityException {
        CertificateUtilFactory.getInstance().getVerifier().verifyCertificate(consumer, userCertificate);
    }

    
    /**
     * Process a given certificate
     * 
     * @param consumer the consumer
     * @param msg the message to add
     * @param cert the certificate to log
     */
    @Deprecated
    public void processCertificate(Consumer<String> consumer, String msg, X509Certificate... cert) {
        com.github.toolarium.security.pki.util.PKIUtil.getInstance().processCertificate(consumer, msg, cert);
    }


    /**
     * Process given private key information
     * 
     * @param consumer the consumer
     * @param msg the message to add
     * @param privateKey the public key
     */
    @Deprecated
    public void processPrivateKeyInfo(Consumer<String> consumer, String msg, PrivateKey privateKey) {
        com.github.toolarium.security.pki.util.PKIUtil.getInstance().processPrivateKeyInfo(consumer, msg, privateKey);
    }

    
    /**
     * Process a given public key information
     * 
     * @param consumer the consumer
     * @param msg the message to add
     * @param publicKey the public key
     */
    @Deprecated
    public void processPublicKeyInfo(Consumer<String> consumer, String msg, PublicKey publicKey) {
        com.github.toolarium.security.pki.util.PKIUtil.getInstance().processPublicKeyInfo(consumer, msg, publicKey);
    }
}
