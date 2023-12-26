/*
 * CertificateFilter.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.impl;

import com.github.toolarium.security.certificate.ICertificateFilter;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;


/**
 * Implements the {@link ICertificateFilter}.
 *  
 * @author patrick
 */
public class CertificateFilter implements ICertificateFilter {
    
    /**
     * @see com.github.toolarium.security.certificate.ICertificateFilter#filterValid(java.util.List)
     */
    @Override
    public List<X509Certificate> filterValid(List<X509Certificate> certificates) {
        List<X509Certificate> result = new LinkedList<X509Certificate>();
        Date dateToCheck = new Date();
        for (X509Certificate certificate : certificates) {
            try {
                certificate.checkValidity(dateToCheck);
                result.add(certificate);
            } catch (CertificateExpiredException e) {
                // expired
            } catch (CertificateNotYetValidException e) {
                // not valid
            }
        }
        
        Collections.sort(result, Comparator.comparing(X509Certificate::getNotAfter));
        return result;
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateFilter#filterExpired(java.util.List)
     */
    @Override
    public List<X509Certificate> filterExpired(List<X509Certificate> certificates) {
        List<X509Certificate> result = new LinkedList<X509Certificate>();
        Date dateToCheck = new Date();
        for (X509Certificate certificate : certificates) {
            try {
                certificate.checkValidity(dateToCheck);
            } catch (CertificateExpiredException e) {
                result.add(certificate);
            } catch (CertificateNotYetValidException e) {
                // NOP
            }
        }
        
        Collections.sort(result, Comparator.comparing(X509Certificate::getNotAfter));
        return result;
    }


    /**
     * @see com.github.toolarium.security.certificate.ICertificateFilter#filterNotYedValid(java.util.List)
     */
    @Override
    public List<X509Certificate> filterNotYedValid(List<X509Certificate> certificates) {
        List<X509Certificate> result = new LinkedList<X509Certificate>();
        Date dateToCheck = new Date();
        for (X509Certificate certificate : certificates) {
            try {
                certificate.checkValidity(dateToCheck);
            } catch (CertificateExpiredException e) {
                // expired
            } catch (CertificateNotYetValidException e) {
                result.add(certificate);
            }
        }
        
        Collections.sort(result, Comparator.comparing(X509Certificate::getNotBefore));
        return result;
    }
}
