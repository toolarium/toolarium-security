/*
 * ICertificateFilter.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import java.security.cert.X509Certificate;
import java.util.List;


/**
 * Defines the certificate filter interface.
 * 
 * @author patrick
 */
public interface ICertificateFilter {
    
    /**
     * Filter the valid certificates
     *
     * @param certificates the certificates to filter
     * @return the valid certificates sorted by last valid till (certificate, not after) date  
     */
    List<X509Certificate> filterValid(List<X509Certificate> certificates);


    /**
     * Filter the expired certificates
     *
     * @param certificates the certificates to filter
     * @return the certificates which are expired sorted by last valid till (certificate, not after) date  
     */
    List<X509Certificate> filterExpired(List<X509Certificate> certificates);

    
    /**
     * Filter the not yet valid certificates
     *
     * @param certificates the certificates to filter
     * @return the certificates which are not yet valid sorted by first valid from (certificate, not before) date  
     */
    List<X509Certificate> filterNotYedValid(List<X509Certificate> certificates);
}
