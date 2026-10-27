/*
 * ICertificateGenerator.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import com.github.toolarium.security.certificate.dto.CertificateStore;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Date;


/**
 * Defines the certificate generator interface.
 *  
 * @author patrick
 */
public interface ICertificateGenerator {
    
    /**
     * Creates a self-signed root CA certificate with a new RSA key pair (2048 bits). It can sign other certificates
     * (basic constraints CA, key usage keyCertSign and cRLSign) but can not be used as server or client certificate.
     *
     * @param dn the name
     * @param validityDays number of days (min 1 day)
     * @return a new created CA certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    CertificateStore createCACertificate(String dn, int validityDays) throws GeneralSecurityException;


    /**
     * Creates a CA certificate: a self-signed root CA if no parent is given, otherwise an intermediate CA signed by the parent.
     * It can sign other certificates (basic constraints CA, key usage keyCertSign and cRLSign) but can not be used as
     * server or client certificate.
     *
     * @param keyPair the key pair to create the certificate from
     * @param parent the parent CA certificate chain or null for a root CA
     * @param dn the name
     * @param startDate the start date
     * @param validityDays number of days (min 1 day)
     * @return a new created CA certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    CertificateStore createCACertificate(KeyPair keyPair, CertificateStore parent, String dn, Date startDate, int validityDays) throws GeneralSecurityException;


    /**
     * Creates an end-entity certificate signed by the given certificate store.
     *
     * <p><strong>Note:</strong> the new certificate reuses the key pair of the given certificate store, so parent and
     * child share the same private key. To create a certificate with an own key pair use
     * {@link #createCreateCertificate(KeyPair, CertificateStore, String, String, Date, int)}.</p>
     *
     * @param certificateStore the certificate store
     * @param dn the name
     * @param alternativeDn the alternative dn (host name), or null to use the dn and localhost as subject alternative names
     * @param startDate the start date
     * @param validityDays number of days
     * @return a new created certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    CertificateStore createCreateCertificate(CertificateStore certificateStore, String dn, String alternativeDn, Date startDate, int validityDays) throws GeneralSecurityException;

    
    /**
     * Creates a self-signed end-entity certificate (e.g. a server certificate). It is not a CA and can not be used to
     * sign other certificates, see {@link #createCACertificate(String, int)}.
     *
     * @param dn the name
     * @return a new created certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    CertificateStore createCreateCertificate(String dn) throws GeneralSecurityException;

    
    /**
     * Creates a certificate
     * 
     * @param dn the name
     * @param alternativeDn the alternative dn (host name), or null to use the dn and localhost as subject alternative names
     * @param validityDays number of days
     * @return a new created certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    CertificateStore createCreateCertificate(String dn, String alternativeDn, int validityDays) throws GeneralSecurityException;

    
    /**
     * Creates a certificate
     * 
     * @param keyPair the key pair to create the certificate from 
     * @param dn the name
     * @param alternativeDn the alternative dn (host name), or null to use the dn and localhost as subject alternative names
     * @param startDate the start date
     * @param validityDays number of days
     * @return a new created certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    CertificateStore createCreateCertificate(KeyPair keyPair, String dn, String alternativeDn, Date startDate, int validityDays) throws GeneralSecurityException;

    
    /**
     * Creates a certificate
     * 
     * @param keyPair the key pair to create the certificate from
     * @param parent the parent certificate chain 
     * @param dn the name
     * @param alternativeDn alternative dn (e.g. hostname), or null to use the dn and localhost as subject alternative names
     * @param startDate the start date
     * @param inputValidityDays number of days (min 1 day)
     * @return a new created certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    CertificateStore createCreateCertificate(KeyPair keyPair, CertificateStore parent, String dn, String alternativeDn, Date startDate, int inputValidityDays) throws GeneralSecurityException;

}
