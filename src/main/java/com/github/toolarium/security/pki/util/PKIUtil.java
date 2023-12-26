/*
 * PKIUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki.util;


import com.github.toolarium.common.ByteArray;
import com.github.toolarium.common.util.RandomGenerator;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements some handy methods in context of PKI
 * 
 * @author patrick
 */
public final class PKIUtil {
    private static final Logger LOG = LoggerFactory.getLogger(PKIUtil.class);
    private static final String NL = "\n";

    
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
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param k the size of the key
     * @return the created KeyPair
     * @throws GeneralSecurityException in case of error
     */
    public KeyPair generateKeyPair(String algorithm, int k) throws GeneralSecurityException {
        return generateKeyPair(null, algorithm, k);
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
        
        if (LOG.isInfoEnabled()) {
            LOG.info("Generating new KeyPair (" + msg + ")...");
        }

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
        
        // Initialise the key generator to generate keys.
        if (LOG.isDebugEnabled()) {
            LOG.debug("Initializing the key generator (" + keySize + " bits).");
        }
            
        keyPairGenerator.initialize(keySize, RandomGenerator.getInstance().getSecureRandom());
        final KeyPair pair = keyPairGenerator.genKeyPair();
        return pair;
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
                                 + "  certificate valid from  : " + cert[i].getNotBefore() + NL
                                 + "  certificate valid till  : " + cert[i].getNotAfter());
        
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
     * Formats a raw base64 encoded data to a well formed data.
     *
     * @param rawCertificate the raw certificate to format
     * @param rowWith the with of the format
     * @param startTag the start tag
     * @param endTag the end tag
     * @return the well formed certificate
     */
    public String formatBuffer(String rawCertificate, int rowWith, String startTag, String endTag) {
        return formatBuffer(new ByteArray(rawCertificate.getBytes()), rowWith, startTag, endTag).toString();
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
    public ByteArray formatBuffer(ByteArray rawCertificate, int rowWith, String startTag, String endTag) {
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
     * Normalise a raw base64 encoded data to a well formed data.
     *
     * @param rawCertificate the raw certificate to format
     * @param startTag the start tag
     * @param endTag the end tag
     * @return the normalised data
     */
    public String normalizeBuffer(String rawCertificate, String startTag, String endTag) {
        return normalizeBuffer(new ByteArray(rawCertificate), startTag, endTag).toString();
    }
    
    
    /**
     * Normalise a raw base64 encoded data to a well formed data.
     *
     * @param rawCertificate the raw certificate to format
     * @param startTag the start tag
     * @param endTag the end tag
     * @return the normalised data
     */
    public ByteArray normalizeBuffer(ByteArray rawCertificate, String startTag, String endTag) {
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
