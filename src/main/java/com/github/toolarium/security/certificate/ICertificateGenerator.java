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
    CertificateStore createCreateCertificate(CertificateStore certificateStore, String dn, String alternativeDn, Date startDate, int validityDays) throws GeneralSecurityException;

    
    /**
     * Creates a self signed certificate
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
     * @param alternativeDn the alternative dn
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
     * @param alternativeDn the alternative dn
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
     * @param alternativeDn alternative dn (e.g. hostname)
     * @param startDate the start date
     * @param inputValidityDays number of days (min 1 day)
     * @return a new created certificate
     * @throws GeneralSecurityException In case of a creation error
     */
    CertificateStore createCreateCertificate(KeyPair keyPair, CertificateStore parent, String dn, String alternativeDn, Date startDate, int inputValidityDays) throws GeneralSecurityException;

}
