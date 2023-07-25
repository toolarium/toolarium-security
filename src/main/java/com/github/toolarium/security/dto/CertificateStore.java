/*
 * CertificateStore.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.dto;

import com.github.toolarium.security.util.PKIUtil;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;


/**
 * Defines the certificate store
 * 
 * @author patrick
 */
public class CertificateStore {
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
        final CertificateStore s = PKIUtil.getInstance().readPKCS12KeyPair(fileName, null, alias, password);
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
     * Write the PKCS12 key store
     *
     * @param fileName the filename
     * @param alias the alias
     * @param password the password
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public void write(String fileName, String alias, String password) throws GeneralSecurityException, IOException {
        PKIUtil.getInstance().writePKCS12KeyStore(prepareFilename(fileName, ".p12"), alias, keypair.getPrivate(), certificates, password);
    }

    
    /**
     * Write the certificate file
     *
     * @param fileName the filename
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public void writeCertificate(String fileName) throws GeneralSecurityException, IOException {
        write(prepareFilename(fileName, ".crt"), PKIUtil.getInstance().formatPKCS7(certificates));
    }


    /**
     * Write the public key file
     *
     * @param fileName the filename
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public void writePublicKey(String fileName) throws GeneralSecurityException, IOException {
        write(prepareFilename(fileName, ".pub"), PKIUtil.getInstance().formatPublicKey(keypair.getPublic()));
    }

    
    /**
     * Write the private key file
     *
     * @param fileName the filename
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public void writePrivateKey(String fileName) throws GeneralSecurityException, IOException {
        write(prepareFilename(fileName, ".pem"), PKIUtil.getInstance().formatPrivateKey(keypair.getPrivate()));
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
