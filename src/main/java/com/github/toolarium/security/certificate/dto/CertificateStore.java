/*
 * CertificateStore.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.dto;

import com.github.toolarium.common.security.ISecuredValue;
import com.github.toolarium.common.security.SecuredValue;
import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.keystore.util.KeyStoreUtil;
import com.github.toolarium.security.pki.KeyConverterFactory;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;


/**
 * Defines the certificate store
 * 
 * @author patrick
 */
public class CertificateStore implements Serializable {
    private static final long serialVersionUID = 1176088618605044855L;
    private final X509Certificate[] certificates; 
    private final KeyPair keypair;

    
    /**
     * Constructor for CertificateStore
     * 
     * @param fileName the filename to read
     * @param alias the alias
     * @param password the password the password
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public CertificateStore(String fileName, String alias, String password) throws GeneralSecurityException, IOException {
        this(fileName, alias, new SecuredValue<>(password, "..."));
    }
    
    
    /**
     * Constructor for CertificateStore
     * 
     * @param fileName the filename to read
     * @param alias the alias
     * @param password the password the password
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public CertificateStore(String fileName, String alias, ISecuredValue<String> password) throws GeneralSecurityException, IOException {
        final CertificateStore s = KeyStoreUtil.getInstance().readPKCS12KeyPair(fileName, null, alias, password);
        this.certificates = s.getCertificates();
        this.keypair = s.getKeyPair();
    }

    
    /**
     * Constructor for CertificateStore
     *
     * @param certificates the certificate chain
     * @param keypair the key pair
     */
    public CertificateStore(KeyPair keypair, X509Certificate... certificates) {
        this.certificates = certificates;
        this.keypair = keypair;
    }
    
    
    /**
     * Get the certificate chain
     *
     * @return the certificate chain
     */
    public X509Certificate[] getCertificates() {
        return certificates;
    }
    
    
    /**
     * Get the keypair
     *
     * @return the keypair
     */
    public KeyPair getKeyPair() {
        return keypair;
    }

    
    /**
     * Create a PKCS12 key store
     *
     * @param alias the alias
     * @param password the password
     * @return the written key store
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public KeyStore toKeyStore(String alias, String password) throws GeneralSecurityException, IOException {
        return KeyStoreUtil.getInstance().createPKCS12KeyStore(null, alias, keypair.getPrivate(), certificates, new SecuredValue<String>(password, "..."));
    }

    
    /**
     * Write the PKCS12 key store
     *
     * @param fileName the filename
     * @param alias the alias
     * @param password the password
     * @return the written key store
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public KeyStore write(String fileName, String alias, String password) throws GeneralSecurityException, IOException {
        return KeyStoreUtil.getInstance().writePKCS12KeyStore(prepareFilename(fileName, ".p12"), alias, keypair.getPrivate(), certificates, new SecuredValue<String>(password, "..."));
    }

    
    /**
     * Write the PKCS12 key store
     *
     * @param fileName the filename
     * @param alias the alias
     * @param password the password
     * @return the written key store
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public KeyStore write(String fileName, String alias, ISecuredValue<String> password) throws GeneralSecurityException, IOException {
        return KeyStoreUtil.getInstance().writePKCS12KeyStore(prepareFilename(fileName, ".p12"), alias, keypair.getPrivate(), certificates, password);
    }

    
    /**
     * Write the certificate file
     *
     * @param fileName the filename
     * @return the written certificates
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public X509Certificate[] writeCertificate(String fileName) throws GeneralSecurityException, IOException {
        write(prepareFilename(fileName, ".crt"), CertificateUtilFactory.getInstance().getConverter().formatPKCS7(certificates));
        return certificates;
    }


    /**
     * Write the public key file
     *
     * @param fileName the filename
     * @return the written public key
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public PublicKey writePublicKey(String fileName) throws GeneralSecurityException, IOException {
        PublicKey publicKey = keypair.getPublic();
        write(prepareFilename(fileName, ".pub"), KeyConverterFactory.getInstance().getConverter(publicKey).formatPublicKey(publicKey));
        return publicKey;
    }

    
    /**
     * Write the private key file
     *
     * @param fileName the filename
     * @return the written private key
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public PrivateKey writePrivateKey(String fileName) throws GeneralSecurityException, IOException {
        PrivateKey privateKey = keypair.getPrivate();
        write(prepareFilename(fileName, ".pem"), KeyConverterFactory.getInstance().getConverter(privateKey).formatPrivateKey(privateKey));
        return privateKey;
    }

    
    /**
     * Write a file content
     *
     * @param inputFileName the filename
     * @param content the content
     * @throws IOException I/O exception in case of an error
     */
    private void write(String inputFileName, String content) throws IOException { // CHECKSTYLE IGNORE THIS LINE
        String fileName = inputFileName;
        FileWriter writer = new FileWriter(new File(fileName));
        writer.append(content);
        writer.flush();
        writer.close();
        
        new File(fileName).setReadable(false, true);
    }
    
    
    /**
     * Prepare filename
     *
     * @param inputfileName the filename
     * @param ending the ending of the file
     * @return the prepared filename
     */
    private String prepareFilename(String inputfileName, String ending) {
        String fileName = inputfileName;

        if (!fileName.endsWith(ending)) {
            if (!fileName.endsWith(".") && !ending.startsWith(".")) {
                fileName += ".";
            }
            fileName += ending;
        }

        return fileName;
    }
}
