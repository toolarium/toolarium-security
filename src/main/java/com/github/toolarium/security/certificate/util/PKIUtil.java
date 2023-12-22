/*
 * PKIUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.util;

import com.github.toolarium.common.ByteArray;
import com.github.toolarium.common.util.RandomGenerator;
import com.github.toolarium.security.certificate.rsa.RSAPrivateKeyPKCS8;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements some handy methods in context of PKI
 * 
 * @author patrick
 */
public final class PKIUtil {

    /** the public key certificate start */
    public static final String PUBLIC_CERTIFICATE_START = "-----BEGIN CERTIFICATE-----";

    /** the public key certificate end */
    public static final String PUBLIC_CERTIFICATE_END = "-----END CERTIFICATE-----";

    /** the public RSA key start */
    public static final String PUBLIC_RSA_KEY_START = "-----BEGIN RSA PUBLIC KEY-----";

    /** the public RSA key end */
    public static final String PUBLIC_RSA_KEY_END = "-----END RSA PUBLIC KEY-----";

    /** the public DSA key start */
    public static final String PUBLIC_DSA_KEY_START = "-----BEGIN DSA PUBLIC KEY-----";

    /** the public DSA key end */
    public static final String PUBLIC_DSA_KEY_END = "-----END DSA PUBLIC KEY-----";

    /** the public EC key start */
    public static final String PUBLIC_EC_KEY_START = "-----BEGIN EC PUBLIC KEY-----";

    /** the public EC key end */
    public static final String PUBLIC_EC_KEY_END = "-----END EC PUBLIC KEY-----";

    /** the private RSA key certificate start */
    public static final String PRIVATE_RSA_KEY_START = "-----BEGIN RSA PRIVATE KEY-----";

    /** the private RSA key certificate end */
    public static final String PRIVATE_RSA_KEY_END = "-----END RSA PRIVATE KEY-----";

    /** the private DSA key certificate start */
    public static final String PRIVATE_DSA_KEY_START = "-----BEGIN DSA PRIVATE KEY-----";

    /** the private DSA key certificate end */
    public static final String PRIVATE_DSA_KEY_END = "-----END DSA PRIVATE KEY-----";

    /** the private ECA key certificate start */
    public static final String PRIVATE_EC_KEY_START = "-----BEGIN EC PRIVATE KEY-----";

    /** the private EC key certificate end */
    public static final String PRIVATE_EC_KEY_END = "-----END EC PRIVATE KEY-----";

    private static final String NL = "\n";
    private static final Logger LOG = LoggerFactory.getLogger(PKIUtil.class);

    
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
    public KeyPair generateKeyPair() throws GeneralSecurityException {
        return generateKeyPair(null, "RSA", 2048);
    }

    
    /**
     * Generates a KeyPair containing a Private- and PublicKey
     * 
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param keySize the size of the key
     * @return the created KeyPair
     * @throws GeneralSecurityException in case of error
     */
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
    public KeyPair generateKeyPair(String provider, String algorithm, int k) throws GeneralSecurityException {
        String msg = algorithm;

        if (provider != null && provider.trim().length() > 0) {
            msg = provider + "/" + algorithm;
        }
        
        LOG.info("Generating new KeyPair (" + msg + ")...");

        // The key generation object
        KeyPairGenerator keyPairGenerator = null;
        if (provider != null && provider.trim().length() > 0) {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
        } else {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        }
        
        // The size of the key to be used (in bits)
        int keySize = k;
        if (keySize <= 0) {
            keySize = 2048;
        }
        
        // Initialize the key generator to generate keys.
        LOG.debug("Initializing the key generator (" + keySize + " bits).");
        keyPairGenerator.initialize(keySize, RandomGenerator.getInstance().getSecureRandom());
        final KeyPair pair = keyPairGenerator.genKeyPair();
        return pair;
    }


    /**
     * Reas a PKCS#7 (with base64 encoded) X509 certificates from a file,
     * which are each bounded at the beginning by
     * <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by
     * <code>-----END CERTIFICATE-----</code>.
     *
     * @param fileName the file to read
     * @return the read certificates
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of error
     */
    public X509Certificate[] getX509Certificates(String fileName) throws GeneralSecurityException, IOException {
        if (fileName == null) {
            return null;
        }
        
        InputStream fis = new BufferedInputStream(new FileInputStream(new File(fileName)));
        DataInputStream dis = new DataInputStream(fis);
        byte[] bytes = new byte[dis.available()];
        dis.readFully(bytes);

        return getX509Certificates(new ByteArray(bytes));
    }


    /**
     * Reas a PKCS#7 (with base64 encoded) X509 certificates from the given
     * buffer, which are each bounded at the beginning by
     * <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by
     * <code>-----END CERTIFICATE-----</code>.
     *
     * @param inputData the data
     * @return the read certificates
     * @throws GeneralSecurityException in case of error
     */
    public X509Certificate[] getX509Certificates(ByteArray inputData) throws GeneralSecurityException {
        if (inputData == null || inputData.length() == 0) {
            return null;
        }
        
        // replace all spaces with newline
        @SuppressWarnings("resource")
        ByteArray data = new ByteArray(inputData);
        data = data.replace((byte) ' ', (byte) '\n');
        data = data.replace(new ByteArray("\nCERTIFICATE"), new ByteArray(" CERTIFICATE"));

        ByteArray formatedCertificate = formatPKCS7(data);
        ArrayList<X509Certificate> certificates = new ArrayList<X509Certificate>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream bais = new ByteArrayInputStream(formatedCertificate.toBytes());

        X509Certificate cert = null;
        while (bais.available() > 0) {
            cert = (X509Certificate) cf.generateCertificate(bais);
            certificates.add(cert);
            // logCertificate( Level.DEBUG, cert );
        }

        X509Certificate[] certs = new X509Certificate[certificates.size()];
        for (int i = 0; i < certs.length; i++) {
            certs[i] = certificates.get(i);
        }

        return certs;
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
    public PublicKey getDSAPublicKey(byte[] buffer) throws IOException, GeneralSecurityException {
        if (buffer == null || buffer.length == 0) {
            return null;
        }
        
        @SuppressWarnings("resource")
        ByteArray t = new ByteArray(buffer).replace(new ByteArray(PUBLIC_DSA_KEY_START), new ByteArray());
        t = t.replace(new ByteArray(PUBLIC_DSA_KEY_END), new ByteArray());
        t = t.replace(new ByteArray("\r"), new ByteArray());
        t = t.replace(new ByteArray(NL), new ByteArray());

        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(t.toBytes()));
        KeyFactory kf = KeyFactory.getInstance("DSA");
        return kf.generatePublic(spec);
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
    public PublicKey getDSAPublicKey(ByteArray buffer) throws IOException, GeneralSecurityException {
        if (buffer == null || buffer.length() == 0) {
            return null;
        }
        
        return getDSAPublicKey(buffer.toBytes());
    }


    /**
     * Reads PKCS#8 formated public key from a buffer,
     * which are each bounded at the beginning by
     * <code>-----BEGIN RSA PRIVATE KEY-----</code>, and bounded at the end by
     * <code>-----END RSA PRIVATE KEY-----</code>.
     * @param buffer the data
     * @return the public key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    public PublicKey getRSAPublicKey(byte[] buffer) throws IOException, GeneralSecurityException {
        if (buffer == null || buffer.length == 0) {
            return null;
        }
        
        @SuppressWarnings("resource")
        ByteArray t = new ByteArray(buffer).replace(new ByteArray(PUBLIC_RSA_KEY_START), new ByteArray());
        t = t.replace(new ByteArray(PUBLIC_RSA_KEY_END), new ByteArray());
        t = t.replace(new ByteArray("\r"), new ByteArray());
        t = t.replace(new ByteArray(NL), new ByteArray());

        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(t.toBytes()));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
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
    public PublicKey getRSAPublicKey(ByteArray buffer) throws IOException, GeneralSecurityException {
        if (buffer == null || buffer.length() == 0) {
            return null;
        }
        
        return getRSAPublicKey(buffer.toBytes());
    }

    
    /**
     * Reads PKCS#8 formated public key from a buffer,
     * which are each bounded at the beginning by
     * <code>-----BEGIN RSA PRIVATE KEY-----</code>, and bounded at the end by
     * <code>-----END RSA PRIVATE KEY-----</code>.
     * @param buffer the data
     * @return the public key
     * @throws IOException in case of error
     * @throws GeneralSecurityException in case of error
     */
    public PublicKey getECPublicKey(byte[] buffer) throws IOException, GeneralSecurityException {
        if (buffer == null || buffer.length == 0) {
            return null;
        }
        
        @SuppressWarnings("resource")
        ByteArray t = new ByteArray(buffer).replace(new ByteArray(PUBLIC_EC_KEY_START), new ByteArray());
        t = t.replace(new ByteArray(PUBLIC_EC_KEY_END), new ByteArray());
        t = t.replace(new ByteArray("\r"), new ByteArray());
        t = t.replace(new ByteArray(NL), new ByteArray());

        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(t.toBytes()));
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(spec);
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
    public PublicKey getECPublicKey(ByteArray buffer) throws IOException, GeneralSecurityException {
        if (buffer == null || buffer.length() == 0) {
            return null;
        }
        
        return getECPublicKey(buffer.toBytes());
    }


    /**
     * Combine two certificate arrays
     *
     * @param certs the certificate
     * @param caCerts the ca certificate(s)
     * @return the combined certificates
     */
    public X509Certificate[] combineCertificates(X509Certificate[] certs, X509Certificate[] caCerts) {
        X509Certificate[] combinedCerts = null;
        int len = 0;
        int offset = 0;

        if (certs != null) {
            len += certs.length;
        }
        
        if (caCerts != null) {
            len += caCerts.length;
        }
        
        if (len > 0) {
            combinedCerts = new X509Certificate[len];
        } else {
            return null;
        }
        
        if (certs != null) {
            for (int i = 0; i < certs.length; i++) {
                combinedCerts[offset++] = certs[i];
            }
        }

        if (caCerts != null) {
            for (int i = 0; i < caCerts.length; i++) {
                combinedCerts[offset++] = caCerts[i];
            }
        }

        return combinedCerts;
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
    public PrivateKey getDSAPrivateKey(String fileName) throws IOException, GeneralSecurityException {
        if (fileName == null) {
            return null;
        }
        
        LOG.debug("Loading DSA private key form file '" + fileName + "'...");
        FileInputStream keyfis = new FileInputStream(fileName);
        byte[] encKey = new byte[keyfis.available()];
        keyfis.read(encKey);
        keyfis.close();

        return getDSAPrivateKey(new ByteArray(encKey));
    }

    
    /**
     * Reads PKCS#8 formated DSA private key from a buffer,
     * which are each bounded at the beginning by
     * <code>-----BEGIN DSA PRIVATE KEY-----</code>, and bounded at the end by
     * <code>-----END DSA PRIVATE KEY-----</code>.
     *
     * @param buffer the private key to encode
     * @return the private key
     * @throws GeneralSecurityException in case of error
     */
    public PrivateKey getDSAPrivateKey(ByteArray buffer) throws GeneralSecurityException {
        if (buffer == null || buffer.length() == 0) {
            return null;
        }
        
        ByteArray normalizedData = normalizeDSAPKCS8(buffer);

        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(normalizedData.toBytes()));
        LOG.debug("File format of private key is: " + privKeySpec.getFormat());
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        return keyFactory.generatePrivate(privKeySpec);
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
    public PrivateKey getRSAPrivateKey(String fileName)
            throws IOException, GeneralSecurityException {
        if (fileName == null) {
            return null;
        }
        
        LOG.debug("Loading RSA private key form file '" + fileName + "'...");
        InputStream keyfis = new BufferedInputStream(new FileInputStream(new File(fileName)));
        byte[] encKey = new byte[keyfis.available()];
        keyfis.read(encKey);
        keyfis.close();

        return getRSAPrivateKey(new ByteArray(encKey));
    }

    
    /**
     * Reads PKCS#8 formated RSA private key from a buffer,
     * which are each bounded at the beginning by
     * <code>-----BEGIN RSA PRIVATE KEY-----</code>, and bounded at the end by
     * <code>-----END RSA PRIVATE KEY-----</code>.
     *
     * @param buffer the private key to encode
     * @return the private key
     * @throws GeneralSecurityException in case of error
     */
    public PrivateKey getRSAPrivateKey(ByteArray buffer) throws GeneralSecurityException {
        if (buffer == null || buffer.length() == 0) {
            return null;
        }
        
        ByteArray normalizedData = normalizeRSAPKCS8(buffer);

        PrivateKey privateKey = null;
        try {
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(normalizedData.toBytes()));
            LOG.debug("File format of RSA private key is: " + privKeySpec.getFormat());
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(privKeySpec);
        } catch (InvalidKeySpecException e) {
            RSAPrivateKeyPKCS8 privKeySpec = new RSAPrivateKeyPKCS8(Base64.getDecoder().decode(normalizedData.toBytes()));
            LOG.debug("File format of RSA private key is: " + privKeySpec.getFormat());
            privKeySpec.checkEncoding();
            privateKey = privKeySpec;
        }

        LOG.debug("PrivateKey encoding check ends successful.");
        LOG.debug("File format of RSA private key is: " + privateKey.getFormat());
        return privateKey;
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
    public PrivateKey getECPrivateKey(String fileName)
            throws IOException, GeneralSecurityException {
        if (fileName == null) {
            return null;
        }
        
        LOG.debug("Loading EC private key form file '" + fileName + "'...");
        InputStream keyfis = new BufferedInputStream(new FileInputStream(new File(fileName)));
        byte[] encKey = new byte[keyfis.available()];
        keyfis.read(encKey);
        keyfis.close();

        return getECPrivateKey(new ByteArray(encKey));
    }

    
    /**
     * Reads PKCS#8 formated EC private key from a buffer,
     * which are each bounded at the beginning by
     * <code>-----BEGIN EC PRIVATE KEY-----</code>, and bounded at the end by
     * <code>-----END EC PRIVATE KEY-----</code>.
     *
     * @param buffer the private key to encode
     * @return the private key
     * @throws GeneralSecurityException in case of error
     */
    public PrivateKey getECPrivateKey(ByteArray buffer) throws GeneralSecurityException {
        if (buffer == null || buffer.length() == 0) {
            return null;
        }
        
        ByteArray normalizedData = normalizeECPKCS8(buffer);

        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(normalizedData.toBytes()));
        LOG.debug("File format of EC private key is: " + privKeySpec.getFormat());
        PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(privKeySpec);
        LOG.debug("File format of EC private key is: " + privateKey.getFormat());
        return privateKey;
    }


    /**
     * Formats a public key into a well formed private key, which
     * is bounded at the beginning and ending with the corresponding messages (see PKCS8).
     *
     * @param publicKey the public key
     * @return the well formed certificate
     */
    public String formatPublicKey(PublicKey publicKey) {
        if (publicKey == null) {
            return null;
        }
        
        if ("DSA".equals(publicKey.getAlgorithm())) {
            return formatDSAPublicKey(publicKey).toString();
        } else if ("RSA".equals(publicKey.getAlgorithm())) {
            return formatRSAPublicKey(publicKey).toString();
        } else if ("EC".equals(publicKey.getAlgorithm())) {
            return formatECPublicKey(publicKey).toString();
        }

        ByteArray rawData = new ByteArray(Base64.getEncoder().encode(publicKey.getEncoded()));
        return formatBuffer(rawData, 64, "", "").toString();
    }


    /**
     * Formats a public DSA key into a well formated X509 certificate (PEM format), which are each bounded at the beginning by
     * <code>-----BEGIN DSA PUBLIC KEY-----</code>,
     * and bounded at the end by <code>-----END DSA PUBLIC KEY-----</code>.
     *
     * @param publicKey the public key to format
     * @return the well formed certificate
     */
    public String formatDSAPublicKey(PublicKey publicKey) {
        return formatBuffer(new ByteArray(Base64.getEncoder().encode(publicKey.getEncoded())), 64, PUBLIC_DSA_KEY_START, PUBLIC_DSA_KEY_END).toString();
    }

    
    /**
     * Formats a public RSA key into a well formated
     * X509 certificate (PEM format), which are each bounded at the beginning by
     * <code>-----BEGIN RSA PUBLIC KEY-----</code>,
     * and bounded at the end by <code>-----END RSA PUBLIC KEY-----</code>.
     *
     * @param publicKey the public key to format
     * @return the well formed certificate
     */
    public String formatRSAPublicKey(PublicKey publicKey) {
        return formatBuffer(new ByteArray(Base64.getEncoder().encode(publicKey.getEncoded())), 64, PUBLIC_RSA_KEY_START, PUBLIC_RSA_KEY_END).toString();
    }

    
    /**
     * Formats a public EC key into a well formated
     * X509 certificate (PEM format), which are each bounded at the beginning by
     * <code>-----BEGIN EC PUBLIC KEY-----</code>,
     * and bounded at the end by <code>-----END EC PUBLIC KEY-----</code>.
     *
     * @param publicKey the public key to format
     * @return the well formed certificate
     */
    public String formatECPublicKey(PublicKey publicKey) {
        return formatBuffer(new ByteArray(Base64.getEncoder().encode(publicKey.getEncoded())), 64, PUBLIC_EC_KEY_START, PUBLIC_EC_KEY_END).toString();
    }

    
    /**
     * Formats a raw base64 encoded X509 certificates to a well formated
     * X509 certificate (PEM format), which are each bounded at the beginning by
     * <code>-----BEGIN CERTIFICATE-----</code>,
     * and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     *
     * @param rawCertificate the raw certificate to format
     * @return the well formed certificate
     */
    public ByteArray formatPKCS7(ByteArray rawCertificate) {
        return formatBuffer(rawCertificate, 64, PUBLIC_CERTIFICATE_START, PUBLIC_CERTIFICATE_END);
    }
    
    /**
     * Create certificate chain into a well formed string representation
     *
     * @param certificateChain the certificate chain
     * @return the string representation
     * @throws CertificateEncodingException In case of a certificate error
     */
    public String formatPKCS7(X509Certificate[] certificateChain) throws CertificateEncodingException {
        String certificateChainContent = "";

        for (int i = 0; i < certificateChain.length; i++) {
            if (i > 0) {
                certificateChainContent += NL;
            }
            
            ByteArray cert = formatPKCS7(certificateChain[i]);
            if (cert != null) {
                @SuppressWarnings("resource")
                ByteArray b = new ByteArray(cert);
                certificateChainContent += b.toString();
            }
        }

        return certificateChainContent;
    }

    /**
     * Formats a certificate to a well formated X509 certificate (PEM format),
     * which are each bounded at the beginning by
     * <code>-----BEGIN CERTIFICATE-----</code>,
     * and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     *
     * @param certificate the certificate to format in PEM format
     * @return the well formed certificate
     * @throws CertificateEncodingException In case of a certificate error
     */
    public ByteArray formatPKCS7(Certificate certificate) throws CertificateEncodingException {
        if (certificate == null) {
            return null;
        }

        return formatPKCS7(new ByteArray(Base64.getEncoder().encode(certificate.getEncoded())));
    }
    
    
    /**
     * Formats a private key into a well formed private key, which
     * is bounded at the beginning and ending with the corresponding messages (see PKCS8).
     *
     * @param privateKey the private key
     * @return the well formed certificate
     */
    public String formatPrivateKey(PrivateKey privateKey) {
        if (privateKey == null) {
            return null;
        }
        
        ByteArray rawData = new ByteArray(Base64.getEncoder().encode(privateKey.getEncoded()));

        if ("DSA".equals(privateKey.getAlgorithm())) {
            return formatDSAPKCS8(rawData).toString();
        } else if ("RSA".equals(privateKey.getAlgorithm())) {
            return formatRSAPKCS8(rawData).toString();
        } else if ("EC".equals(privateKey.getAlgorithm())) {
            return formatECPKCS8(rawData).toString();
        }
        
        return formatBuffer(rawData, 64, "", "").toString();
    }

    
    /**
     * Formats a raw base64 encoded PKCS8 DSA to a well formed private key, which
     * is bounded at the beginning by
     * <code>-----BEGIN DSA PRIVATE KEY-----</code>,
     * and bounded at the end by <code>-----END DSA PRIVATE KEY-----</code>.
     *
     * @param rawData the raw data to format
     * @return the well formed certificate
     */
    public ByteArray formatDSAPKCS8(ByteArray rawData) {
        return formatBuffer(rawData, 64, PRIVATE_DSA_KEY_START, PRIVATE_DSA_KEY_END);
    }

    
    /**
     * Formats a raw base64 encoded PKCS8 RSA to a well formed private key, which
     * is bounded at the beginning by
     * <code>-----BEGIN RSA PRIVATE KEY-----</code>,
     * and bounded at the end by <code>-----END RSA PRIVATE KEY-----</code>.
     *
     * @param rawData the raw data to format
     * @return the well formed certificate
     */
    public ByteArray formatRSAPKCS8(ByteArray rawData) {
        return formatBuffer(rawData, 64, PRIVATE_RSA_KEY_START, PRIVATE_RSA_KEY_END);
    }

    
    /**
     * Formats a raw base64 encoded PKCS8 EC to a well formed private key, which
     * is bounded at the beginning by
     * <code>-----BEGIN EC PRIVATE KEY-----</code>,
     * and bounded at the end by <code>-----END EC PRIVATE KEY-----</code>.
     *
     * @param rawData the raw data to format
     * @return the well formed certificate
     */
    public ByteArray formatECPKCS8(ByteArray rawData) {
        return formatBuffer(rawData, 64, PRIVATE_EC_KEY_START, PRIVATE_EC_KEY_END);
    }

    
    /**
     * Normalize a raw base64 encoded PKCS8 DSA to a well formed private key.
     *
     * @param rawData the raw data to normalize
     * @return the normalized private key
     */
    public ByteArray normalizeDSAPKCS8(ByteArray rawData) {
        return normalizeBuffer(rawData, PRIVATE_DSA_KEY_START, PRIVATE_DSA_KEY_END);
    }

    
    /**
     * Normalize a raw base64 encoded PKCS8 RSA to a well formed private key.
     *
     * @param rawData the raw data to normalize
     * @return the normalized private key
     */
    public ByteArray normalizeRSAPKCS8(ByteArray rawData) {
        return normalizeBuffer(rawData, PRIVATE_RSA_KEY_START, PRIVATE_RSA_KEY_END);
    }

    
    /**
     * Normalize a raw base64 encoded PKCS8 EC to a well formed private key.
     *
     * @param rawData the raw data to normalize
     * @return the normalized private key
     */
    public ByteArray normalizeECPKCS8(ByteArray rawData) {
        return normalizeBuffer(rawData, PRIVATE_EC_KEY_START, PRIVATE_EC_KEY_END);
    }


    /**
     * Process a given certificate
     * 
     * @param consumer the consumer
     * @param msg the message to add
     * @param cert the certificate to log
     */
    public void processCertificate(Consumer<String> consumer, String msg, X509Certificate... cert) {
        StringBuilder message = new StringBuilder();
        if (msg != null) {
            message.append(msg);
            message.append(NL);
        }

        if (cert != null && cert.length > 0) {
            for (int i = 0; i < cert.length; i++) {
                if (cert[i] == null) {
                    message.append("X.509 Certificate is null");
                    if (cert.length > 1) {
                        message.append(" #").append((i + 1));
                    }
                    message.append("!\n");
                } else {
                    message.append("X.509 Certificate information");
                    if (cert.length > 1) {
                        message.append(" #").append((i + 1));
                    }
                    message.append(":\n");
                    message.append("  signature algorithm name: " + cert[i].getSigAlgName() + NL
                                 + "  signature algorithm OID : " + cert[i].getSigAlgOID() + NL
                                 + "  certificate type        : " + cert[i].getType() + NL
                                 + "  certificate version     : " + cert[i].getVersion() + NL
                                 + "  certificate subject     : " + cert[i].getSubjectX500Principal() + NL
                                 + "  certificate issuer      : " + cert[i].getIssuerX500Principal() + NL
                                 + "  certificate not before  : " + cert[i].getNotBefore() + NL
                                 + "  certificate not after   : " + cert[i].getNotAfter());
        
                    PublicKey publicKey = cert[i].getPublicKey();
                    if (publicKey != null) {
                        message.append("\n\n  PublicKey information:\n"
                                       + "    algorithm  : " + publicKey.getAlgorithm() + NL
                                       + "    format     : " + publicKey.getFormat()
                                       + NL);
                    }
                }
            }
    
            consumer.accept(message.toString());
        }
    }


    /**
     * Process given private key information
     * 
     * @param consumer the consumer
     * @param msg the message to add
     * @param privateKey the public key
     */
    public void processPrivateKeyInfo(Consumer<String> consumer, String msg, PrivateKey privateKey) {
        StringBuilder message = new StringBuilder();
        if (msg != null) {
            message.append(msg + NL);
        }

        if (privateKey == null) {
            message.append("PrivateKey is null!");
        } else {
            message.append("PrivateKey information:\n" + "  algorithm: " + privateKey.getAlgorithm() + NL + "  format   : " + privateKey.getFormat());
        }

        consumer.accept(message.toString());
    }

    
    /**
     * Process a given public key information
     * 
     * @param consumer the consumer
     * @param msg the message to add
     * @param publicKey the public key
     */
    public void processPublicKeyInfo(Consumer<String> consumer, String msg, PublicKey publicKey) {
        StringBuilder message = new StringBuilder();
        if (msg != null) {
            message.append(msg + NL);
        }

        if (publicKey == null) {
            message.append("PublicKey is null!");
        } else {
            message.append("PublicKey information:\n" + "  algorithm: " + publicKey.getAlgorithm() + NL + "  format   : " + publicKey.getFormat());
        }

        consumer.accept(message.toString());
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
    public void verifyCertificateChain(Consumer<String> consumer, X509Certificate[] certs) throws GeneralSecurityException {
        if (certs == null || certs.length == 0) {
            return;
        }
        
        int anz = certs.length;
        if (consumer != null) {
            PKIUtil.getInstance().processCertificate(consumer, "Verify certificate chain: " + anz + " certificate(s)...", certs);
        }

        verifyCertificate(consumer, certs[anz - 1], null);
        for (int i = anz - 1; i > 0; i--) {
            verifyCertificate(consumer, certs[i - 1], certs[i]);
        }
        
        LOG.debug("Certificate chain checked successful!");
    }

    
    /**
     * Verifies the digital signature of a certificate.
     *
     * @param consumer the consumer
     * @param userCert the certificate to verify
     * @param caCert the certificate of the CA which has issued the userCert or <code>null</code> if the userCert is a self signed certificate
     * @throws GeneralSecurityException in case of error
     */
    public void verifyCertificate(Consumer<String> consumer, X509Certificate userCert, X509Certificate caCert) throws GeneralSecurityException {
        if (caCert != null) {
            LOG.debug("Verify certificate: '" + userCert.getSubjectX500Principal().getName() + "'"); // getSubjectDN()
            userCert.verify(caCert.getPublicKey());

            LOG.debug("Successfully verified CA certificate with public key.");
            if (consumer != null) {
                processPublicKeyInfo(consumer, null, caCert.getPublicKey());
            }
        }
    }


    /**
     * Verifies the digital signature of a certificate.
     *
     * @param consumer the consumer
     * @param userCertificate the certificate to verify
     * @throws GeneralSecurityException in case of error
     */
    public void verifyCertificate(Consumer<String> consumer, X509Certificate userCertificate) throws GeneralSecurityException {
        if (userCertificate == null) {
            throw new GeneralSecurityException("Invalid certificate (null)!");
        }
        
        LOG.debug("Verify certificate: '" + userCertificate.getSubjectX500Principal().getName() + "'"); // getSubjectDN
        userCertificate.verify(userCertificate.getPublicKey());

        LOG.debug("Successfully verified CA certificate with its own public key.");
        if (consumer != null) {
            processPublicKeyInfo(consumer, null, userCertificate.getPublicKey());
        }
    }

    
    /**
     * Converts to java.security
     *
     * @param cert the certificate
     * @return the converted certificate
     */
    @SuppressWarnings("deprecation")
    public static java.security.cert.X509Certificate convert(@SuppressWarnings("removal") javax.security.cert.X509Certificate cert) {
        try {
            final byte[] encoded = cert.getEncoded();
            ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            return (java.security.cert.X509Certificate) cf.generateCertificate(bis);
        } catch (Exception e) {
            LOG.error("Could not convert javax.security.cert.X509Certificate " + "to a java.security.cert.X509Certificate: " + e.getMessage());
        }

        return null;
    }

    
    /**
     * Converts to javax.security
     *
     * @param cert the certificate
     * @return the converted certificate
     */
    public static @SuppressWarnings({"removal", "deprecation"}) javax.security.cert.X509Certificate convert(java.security.cert.X509Certificate cert) {
        try {
            byte[] encoded = cert.getEncoded();
            return javax.security.cert.X509Certificate.getInstance(encoded);
        } catch (Exception e) {
            LOG.error("Could not convert javax.security.cert.X509Certificate to a java.security.cert.X509Certificate: " + e.getMessage());
        }

        return null;
    }


    /**
     * Formats a raw base64 encoded data to a well formed data.
     *
     * @param rawCertificate the raw certificate to format
     * @param rowWith the with of the format
     * @param startTag the start tag
     * @param endTag the end tag
     * @return the well formed certificate
     */
    protected ByteArray formatBuffer(ByteArray rawCertificate, int rowWith, String startTag, String endTag) {
        if (rawCertificate == null) {
            return rawCertificate;
        }
        
        if (rawCertificate.toString().startsWith(startTag)) {
            return rawCertificate;
        }

        ByteArray formatedData = new ByteArray();
        formatedData.append(startTag);

        int pos = 0;
        boolean allreadyAdded = false;

        for (int i = 0; i < rawCertificate.length(); i++) {
            if (!allreadyAdded && (pos % rowWith) == 0) {
                formatedData.append((byte) '\n');
                allreadyAdded = true;
            }

            byte b = rawCertificate.get(i);
            if ((b != '\n') && (b != '\r')) {
                allreadyAdded = false;
                formatedData.append(b);
                pos++;
            }
        }

        formatedData.append((byte) '\n');
        formatedData.append(endTag);

        // LOG.debug("formated data: " + formatedData );
        return formatedData;
    }

    /**
     * Normalize a raw base64 encoded data to a well formed data.
     *
     * @param rawCertificate the raw certificate to format
     * @param startTag the start tag
     * @param endTag the end tag
     * @return the normalized data
     */
    protected ByteArray normalizeBuffer(ByteArray rawCertificate, String startTag, String endTag) {
        if (rawCertificate == null) {
            return rawCertificate;
        }
        
        String data = rawCertificate.toString();
        if (startTag != null) {
            int index = data.indexOf(startTag);
            if (index >= 0) {
                data = data.substring(index + startTag.length());
            }
        }
        
        if (endTag != null) {
            int index = data.indexOf(endTag);
            if (index >= 0) {
                data = data.substring(0, index);
            }
        }

        ByteArray newData = new ByteArray();
        char ch = 0;
        for (int i = 0; i < data.length(); i++) {
            ch = data.charAt(i);
            if ((ch != '\n') && (ch != '\r')) {
                newData.append((byte) ch);
            }
        }

        return newData;
    }
}
