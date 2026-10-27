/*
 * PKIConfigurationUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.configuration;

import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.keystore.util.KeyStoreUtil;
import com.github.toolarium.security.pki.KeyConverterFactory;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * PKI configuration util. It supports cases where you have a simple string of certificates,
 * private key, public key and you need the converted object.
 * 
 * @author patrick
 */
public final class PKIConfigurationUtil {
    private static final Logger LOG = LoggerFactory.getLogger(PKIConfigurationUtil.class);
    /** system property to change the trust manager algorithm, default PKIX; SunX509 restores the behaviour of version 1.1.8 and older */
    private static final String TRUST_MANAGER_ALGORITHM_PROPERTY = "toolarium.security.trustManagerAlgorithm";
    private static final String START_CERTIFICATE = "-----BEGIN";
    private static final String END_CERTIFICATE_KEY = "CERTIFICATE-----";
    private static final String END_PRIVATE_KEY = "PRIVATE KEY-----";
    private static final String END_PUBLIC_KEY = "PUBLIC KEY-----";
    private static final String ENCRYPTED = "ENCRYPTED";
    private static final Pattern PEM_BOUNDARY = Pattern.compile("-----(BEGIN|END)[^-]*-----");
     
    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static final class HOLDER {
        static final PKIConfigurationUtil INSTANCE = new PKIConfigurationUtil();
    }

    
    /**
     * Constructor
     */
    private PKIConfigurationUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static PKIConfigurationUtil getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Add a certificate into a key-store
     * 
     * @param alias the alias. If there are multiple certificates the index number will be added to the alias, e.g. alias0, alias1... 
     * @param certificate the certificate, a PKCS#7 (with base64 encoded) X509 certificates, which are each bounded at the 
     *        beginning by <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     * @return the key-store with added certificate
     * @throws GeneralSecurityException In case of general security exception
     */
    public KeyStore getKeyStore(String alias, String certificate) throws GeneralSecurityException {
        if (certificate == null || certificate.isBlank()) {
            throw new GeneralSecurityException("Invalid certificate!");
        }

        final KeyStore keyStore;
        try {
            keyStore = KeyStoreUtil.getInstance().createKeyStore(null);
        } catch (IOException e) {
            throw new GeneralSecurityException(e.getMessage(), e);
        }
        
        final X509Certificate[] certificateChain = getCertificate(certificate);

        // get certificate
        if (keyStore != null && certificateChain != null) {
            List<X509Certificate> list = new ArrayList<X509Certificate>();
            list.addAll(CertificateUtilFactory.getInstance().getFilter().filterValid(Arrays.asList(certificateChain)));
            list.addAll(CertificateUtilFactory.getInstance().getFilter().filterNotYedValid(Arrays.asList(certificateChain)));
        
            for (int i = 0; i < list.size(); i++) {
                // add the key manager store in the store
                keyStore.setCertificateEntry(alias + i, list.get(i));
                if (LOG.isDebugEnabled()) {
                    PKIUtil.getInstance().processCertificate(LOG::debug, "Add certificate to key store:", list.get(i));
                }
            }
        }
        
        return keyStore;
    }


    /**
     * Add a certificate into the default trust store
     *
     * @param alias the alias. If there are multiple certificates the index number will be added to the alias, e.g. alias0, alias1... 
     * @param certificate the certificate, a PKCS#7 (with base64 encoded) X509 certificates, which are each bounded at the 
     *        beginning by <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     * @return the trust key-store with added certificate
     * @throws GeneralSecurityException In case of general security exception
     */
    public KeyStore getTrustKeyStore(String alias, String certificate) throws GeneralSecurityException {
        if (certificate == null || certificate.isBlank()) {
            throw new GeneralSecurityException("Invalid trust certificate!");
        }
        
        // get certificate
        X509Certificate[] certificateChain = getCertificate(certificate);
        
        // get trust key-store with added certificate chain
        try {
            return KeyStoreUtil.getInstance().addCertificateToTrustKeystore(alias, certificateChain);
        } catch (IOException e) {
            throw new GeneralSecurityException(e.getMessage(), e);
        }
    }

    
    /**
     * Add a certificate into the default trust store and return the trust manager.
     *
     * @param alias the alias. If there are multiple certificates the index number will be added to the alias, e.g. alias0, alias1... 
     * @param certificate the certificate, a PKCS#7 (with base64 encoded) X509 certificates, which are each bounded at the 
     *        beginning by <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     * @return the trust key-store with added certificate
     * @throws GeneralSecurityException In case of general security exception
     */
    public TrustManager[] getTrustManagers(String alias, String certificate) throws GeneralSecurityException {
        if (certificate == null || certificate.isBlank()) {
            throw new GeneralSecurityException("Invalid trust certificate!");
        }
        
        // get certificate as key-store
        final KeyStore trustKeyStore = getTrustKeyStore(alias, certificate);
        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(System.getProperty(TRUST_MANAGER_ALGORITHM_PROPERTY, TrustManagerFactory.getDefaultAlgorithm()));
        trustManagerFactory.init(trustKeyStore);
        return trustManagerFactory.getTrustManagers();
    }

    
    /**
     * Get the private key from a PKCS#8 formated private key, which is bounded at the beginning by
     * <code>-----BEGIN ... PRIVATE KEY-----</code>, and bounded at the end by <code>-----END ... PRIVATE KEY-----</code>.
     *
     * @param inputPrivateKeyString the PKCS#8 formated private key
     * @return the private key
     * @throws GeneralSecurityException In case of general security exception
     */
    public PrivateKey getPrivateKey(String inputPrivateKeyString) throws GeneralSecurityException {
        return getPrivateKey(inputPrivateKeyString, null);
    }
    
    
    /**
     * Get the private key from a PKCS#8 formated private key, which is bounded at the beginning by
     * <code>-----BEGIN ... PRIVATE KEY-----</code>, and bounded at the end by <code>-----END ... PRIVATE KEY-----</code>.
     *
     * @param inputPrivateKeyString the PKCS#8 formated private key
     * @param intputKeyType the key type or null
     * @return the private key
     * @throws GeneralSecurityException In case of general security exception
     */
    public PrivateKey getPrivateKey(String inputPrivateKeyString, String intputKeyType) throws GeneralSecurityException {
        if (inputPrivateKeyString == null || inputPrivateKeyString.isBlank()) {
            throw new GeneralSecurityException("Invalid private key!");
        }
        
        String keyType = intputKeyType;
        String privateKeyString = inputPrivateKeyString.trim();
        if (privateKeyString.startsWith(START_CERTIFICATE)) {
            int idx = privateKeyString.indexOf(END_PRIVATE_KEY, START_CERTIFICATE.length());
            if (idx < 0) {
                throw new GeneralSecurityException("Invalid private key!");
            }

            String readKeyType = readKeyType(privateKeyString, idx);
            if (readKeyType.startsWith(ENCRYPTED)) {
                throw new GeneralSecurityException("Encrypted private keys are not supported!");
            }

            if (readKeyType.isEmpty()) {
                // generic PKCS#8 header (-----BEGIN PRIVATE KEY-----): the key type is not part of the header
                return getGenericPrivateKey(privateKeyString, keyType);
            }

            keyType = readKeyType;
        }

        if (keyType == null || keyType.isBlank()) {
            keyType = "RSA";
        }

        try {
            return KeyConverterFactory.getInstance().getConverter(keyType.trim()).getPrivateKey(privateKeyString);
        } catch (IOException | IllegalArgumentException e) {
            throw new GeneralSecurityException("Invalid private key: " + e.getMessage(), e);
        }
    }

    
    /**
     * Get the public key from a PKCS#8 formated public key which is bounded at the beginning by
     * <code>-----BEGIN PUBLIC KEY-----</code>, and bounded at the end by <code>-----END PUBLIC KEY-----</code>.
     *
     * @param inputPublicKeyString the PKCS#8 formated public key
     * @return the public key
     * @throws GeneralSecurityException In case of general security exception
     */
    public PublicKey getPublicKey(String inputPublicKeyString) throws GeneralSecurityException {
        return getPublicKey(inputPublicKeyString, null);
    }
    
    
    /**
     * Get the public key from a PKCS#8 formated public key which is bounded at the beginning by
     * <code>-----BEGIN PUBLIC KEY-----</code>, and bounded at the end by <code>-----END PUBLIC KEY-----</code>.
     *
     * @param inputPublicKeyString the PKCS#8 formated public key
     * @param intputKeyType the key type or null
     * @return the public key
     * @throws GeneralSecurityException In case of general security exception
     */
    public PublicKey getPublicKey(String inputPublicKeyString, String intputKeyType) throws GeneralSecurityException {
        if (inputPublicKeyString == null || inputPublicKeyString.isBlank()) {
            throw new GeneralSecurityException("Invalid public key!");
        }
        
        String keyType = intputKeyType;
        String publicKeyString = inputPublicKeyString.trim();
        if (publicKeyString.startsWith(START_CERTIFICATE)) {
            int idx = publicKeyString.indexOf(END_PUBLIC_KEY, START_CERTIFICATE.length());
            if (idx < 0) {
                throw new GeneralSecurityException("Invalid public key!");
            }
            
            String readKeyType = readKeyType(publicKeyString, idx);
            if (readKeyType.isEmpty()) {
                // generic X.509 header (-----BEGIN PUBLIC KEY-----): the key type is not part of the header
                return getGenericPublicKey(publicKeyString, keyType);
            }

            keyType = readKeyType;
        }

        if (keyType == null || keyType.isBlank()) {
            keyType = "RSA";
        }

        try {
            return KeyConverterFactory.getInstance().getConverter(keyType.trim()).getPublicKey(publicKeyString);
        } catch (IOException | IllegalArgumentException e) {
            throw new GeneralSecurityException("Invalid public key: " + e.getMessage(), e);
        }
    }


    /**
     * Read the key type from a PEM header, e.g. <code>RSA</code> from <code>-----BEGIN RSA PRIVATE KEY-----</code>.
     *
     * @param pem the PEM string
     * @param endIndex the index of the end of the header (start of <code>PRIVATE KEY-----</code> / <code>PUBLIC KEY-----</code>)
     * @return the key type or an empty string if the header contains no key type
     */
    private String readKeyType(String pem, int endIndex) {
        int startIndex = START_CERTIFICATE.length() + 1;
        if (endIndex <= startIndex) {
            return "";
        }
        return pem.substring(startIndex, endIndex).trim();
    }


    /**
     * Get a private key from a generic PKCS#8 PEM (-----BEGIN PRIVATE KEY-----). The algorithm is
     * taken from the given key type or, if not defined, from the algorithm identifier inside the key.
     *
     * @param pem the PEM string
     * @param keyType the key type or null
     * @return the private key
     * @throws GeneralSecurityException In case of an invalid key
     */
    private PrivateKey getGenericPrivateKey(String pem, String keyType) throws GeneralSecurityException {
        byte[] decoded = decodePem(pem);
        try {
            String type = keyType;
            if (type == null || type.isBlank()) {
                try {
                    type = getKeyType(PrivateKeyInfo.getInstance(decoded).getPrivateKeyAlgorithm().getAlgorithm());
                } catch (RuntimeException e) {
                    throw new GeneralSecurityException("Invalid private key: " + e.getMessage(), e);
                }
            }

            return KeyFactory.getInstance(type.trim()).generatePrivate(new PKCS8EncodedKeySpec(decoded));
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }


    /**
     * Get a public key from a generic X.509 PEM (-----BEGIN PUBLIC KEY-----). The algorithm is
     * taken from the given key type or, if not defined, from the algorithm identifier inside the key.
     *
     * @param pem the PEM string
     * @param keyType the key type or null
     * @return the public key
     * @throws GeneralSecurityException In case of an invalid key
     */
    private PublicKey getGenericPublicKey(String pem, String keyType) throws GeneralSecurityException {
        byte[] decoded = decodePem(pem);
        String type = keyType;
        if (type == null || type.isBlank()) {
            try {
                type = getKeyType(SubjectPublicKeyInfo.getInstance(decoded).getAlgorithm().getAlgorithm());
            } catch (RuntimeException e) {
                throw new GeneralSecurityException("Invalid public key: " + e.getMessage(), e);
            }
        }

        return KeyFactory.getInstance(type.trim()).generatePublic(new X509EncodedKeySpec(decoded));
    }


    /**
     * Get the key type (key factory algorithm) of an algorithm identifier, e.g. <code>RSA</code> for 1.2.840.113549.1.1.1.
     *
     * @param algorithm the algorithm identifier of the key
     * @return the key type; for an unknown identifier its dotted form, which the JDK resolves for further algorithms (e.g. Ed25519)
     */
    private String getKeyType(ASN1ObjectIdentifier algorithm) {
        if (PKCSObjectIdentifiers.rsaEncryption.equals(algorithm)) {
            return "RSA";
        } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
            return "EC";
        } else if (X9ObjectIdentifiers.id_dsa.equals(algorithm)) {
            return "DSA";
        }
        return algorithm.getId();
    }


    /**
     * Decode the base64 content of a PEM string
     *
     * @param pem the PEM string
     * @return the decoded content
     * @throws GeneralSecurityException In case of an invalid encoding
     */
    private byte[] decodePem(String pem) throws GeneralSecurityException {
        String base64 = PEM_BOUNDARY.matcher(pem).replaceAll("").replaceAll("\\s", "");
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Invalid base64 encoding: " + e.getMessage(), e);
        }
    }


    /**
     * Convert PKCS#7 certificates string into a certificate chain
     *
     * @param inputCertificate the certificate, a PKCS#7 (with base64 encoded) X509 certificates, which are each bounded at the 
     *        beginning by <code>-----BEGIN CERTIFICATE-----</code>, and bounded at the end by <code>-----END CERTIFICATE-----</code>.
     * @return the trust key-store with added certificate
     * @throws GeneralSecurityException In case of general security exception
     */
    public X509Certificate[] getCertificate(String inputCertificate) throws GeneralSecurityException {
        if (inputCertificate == null || inputCertificate.isBlank()) {
            throw new GeneralSecurityException("Invalid certificate!");
        }
        
        String certificate = inputCertificate.trim();
        if (certificate.startsWith(START_CERTIFICATE)) {
            int idx = certificate.indexOf(END_CERTIFICATE_KEY, START_CERTIFICATE.length());
            if (idx < 0) {
                throw new GeneralSecurityException("Invalid certificate!");
            }
        }
        
        X509Certificate[] certificateChain = CertificateUtilFactory.getInstance().getConverter().getX509Certificates(certificate); 
        if (LOG.isDebugEnabled()) {
            PKIUtil.getInstance().processCertificate(LOG::debug, "Convert certificates:", certificateChain);
        }
        
        return certificateChain;
    }
}
