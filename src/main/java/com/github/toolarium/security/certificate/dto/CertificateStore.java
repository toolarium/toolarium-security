/*
 * CertificateStore.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.dto;

import com.github.toolarium.common.security.ISecuredSecretValue;
import com.github.toolarium.common.security.SecuredValueFactory;
import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.keystore.util.KeyStoreUtil;
import com.github.toolarium.security.pki.KeyConverterFactory;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;


/**
 * Defines the certificate store.
 *
 * <p><strong>Serialization warning:</strong> This class implements {@link java.io.Serializable}
 * and holds a {@link java.security.KeyPair} (including the private key). Java serialization
 * will write the raw private-key bytes to whatever {@link java.io.ObjectOutputStream} target
 * is used, typically a file or network stream, with no encryption.  Never serialize
 * instances of this class unless the destination is explicitly protected (e.g. an encrypted
 * key store).  Prefer {@link #write(String, String, char[])} or {@link #toKeyStore} for
 * persistent storage.</p>
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
    public CertificateStore(String fileName, String alias, char[] password) throws GeneralSecurityException, IOException {
        this(fileName, alias, SecuredValueFactory.getInstance().createSecret(password, "..."));
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
    public CertificateStore(String fileName, String alias, ISecuredSecretValue password) throws GeneralSecurityException, IOException {
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
        this.certificates = copy(certificates);
        this.keypair = keypair;
    }


    /**
     * Get the certificate chain
     *
     * @return a copy of the certificate chain
     */
    public X509Certificate[] getCertificates() {
        return copy(certificates);
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
    public KeyStore toKeyStore(String alias, char[] password) throws GeneralSecurityException, IOException {
        return toKeyStore(alias, SecuredValueFactory.getInstance().createSecret(password, "..."));
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
    public KeyStore toKeyStore(String alias, ISecuredSecretValue password) throws GeneralSecurityException, IOException {
        return KeyStoreUtil.getInstance().createPKCS12KeyStore(null, alias, keypair.getPrivate(), certificates, password);
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
    public KeyStore write(String fileName, String alias, char[] password) throws GeneralSecurityException, IOException {
        return KeyStoreUtil.getInstance().writePKCS12KeyStore(prepareFilename(fileName, ".p12"), alias, keypair.getPrivate(), certificates, SecuredValueFactory.getInstance().createSecret(password, "..."));
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
    public KeyStore write(String fileName, String alias, ISecuredSecretValue password) throws GeneralSecurityException, IOException {
        return KeyStoreUtil.getInstance().writePKCS12KeyStore(prepareFilename(fileName, ".p12"), alias, keypair.getPrivate(), certificates, password);
    }

    
    /**
     * Write the certificate file
     *
     * @param fileName the filename
     * @return a copy of the written certificates
     * @throws GeneralSecurityException In case if a export issue
     * @throws IOException In case of an I/O issue
     */
    public X509Certificate[] writeCertificate(String fileName) throws GeneralSecurityException, IOException {
        write(prepareFilename(fileName, ".crt"), CertificateUtilFactory.getInstance().getConverter().formatPKCS7(certificates));
        return copy(certificates);
    }


    /**
     * Copy a certificate chain, so the internal array can not be changed from outside.
     *
     * @param certificateChain the certificate chain or null
     * @return the copy or null
     */
    private static X509Certificate[] copy(X509Certificate[] certificateChain) {
        if (certificateChain == null) {
            return null;
        }

        return certificateChain.clone();
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
     * Write the private key file.
     *
     * <p><b>WARNING: The private key is written unencrypted. Protect the output file appropriately.</b></p>
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
        Path path = new File(fileName).toPath();
        if (Files.isSymbolicLink(path)) {
            throw new IOException("Invalid file '" + fileName + "', a symbolic link is not allowed!");
        }

        boolean isPosix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
        boolean exists = Files.exists(path, LinkOption.NOFOLLOW_LINKS);
        if (isPosix) {
            // restrict the file permissions to owner-only before the content is written, so it is never readable by others
            Set<PosixFilePermission> ownerOnly = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            if (exists) {
                Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).setPermissions(ownerOnly);
            } else {
                Files.createFile(path, PosixFilePermissions.asFileAttribute(ownerOnly));
            }
        } else {
            // create the file and restrict the file permissions to owner-only before the content is written
            if (!exists) {
                Files.createFile(path);
            }
            restrictToOwner(path);
        }

        // the file exists now: open it without following a symbolic link (it could be replaced in the meantime)
        try (Writer writer = Files.newBufferedWriter(path, Charset.defaultCharset(), StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING, LinkOption.NOFOLLOW_LINKS)) {
            writer.append(content);
            writer.flush();
        }
    }


    /**
     * Restrict the file permissions to owner-only on a non-POSIX file system (best effort). If an ACL file attribute view
     * is available (e.g. on Windows), the access control list is replaced by a single entry for the owner.
     *
     * @param path the file
     */
    private void restrictToOwner(Path path) {
        File file = path.toFile();
        file.setReadable(false, false);
        file.setReadable(true, true);
        file.setWritable(false, false);
        file.setWritable(true, true);

        AclFileAttributeView aclView = Files.getFileAttributeView(path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (aclView == null) {
            return;
        }

        try {
            UserPrincipal owner = aclView.getOwner();
            AclEntry ownerEntry = AclEntry.newBuilder()
                                          .setType(AclEntryType.ALLOW)
                                          .setPrincipal(owner)
                                          .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                                          .build();
            aclView.setAcl(Collections.singletonList(ownerEntry));
        } catch (IOException | RuntimeException expected) {
            // best effort: the file permissions are already restricted as far as possible
        }
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
