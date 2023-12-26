/*
 * CertificateUtilFactory.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import com.github.toolarium.security.certificate.impl.CertificateChainAnalyzer;
import com.github.toolarium.security.certificate.impl.CertificateConverter;
import com.github.toolarium.security.certificate.impl.CertificateFilter;
import com.github.toolarium.security.certificate.impl.CertificateGenerator;
import com.github.toolarium.security.certificate.impl.CertificateVerifier;


/**
 * Defines the certificate converter factory.
 *  
 * @author patrick
 */
public final class CertificateUtilFactory {
    private ICertificateGenerator certificateGenerator;
    private ICertificateConverter certificateConverter;
    private ICertificateFilter certificateFilter;
    private ICertificateVerifier certificateVerifier;
    private ICertificateChainAnalyzer certificateChainAnalyzer;
    
    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final CertificateUtilFactory INSTANCE = new CertificateUtilFactory();
    }

    
    /**
     * Constructor
     */
    private CertificateUtilFactory() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static CertificateUtilFactory getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Get the generator
     *
     * @return the generator
     */
    public ICertificateGenerator getGenerator() {
        if (certificateGenerator == null) {
            certificateGenerator = new CertificateGenerator(); 
        }
        
        return certificateGenerator;
    }
    
    
    /**
     * Get the converter
     *
     * @return the converter
     */
    public ICertificateConverter getConverter() {
        if (certificateConverter == null) {
            certificateConverter = new CertificateConverter(); 
        }
        
        return certificateConverter;
    }
    
    
    /**
     * Get the filter
     *
     * @return the filter
     */
    public ICertificateFilter getFilter() {
        if (certificateFilter == null) {
            certificateFilter = new CertificateFilter(); 
        }
        
        return certificateFilter;
    }

    
    /**
     * Get the filter
     *
     * @return the filter
     */
    public ICertificateVerifier getVerifier() {
        if (certificateVerifier == null) {
            certificateVerifier = new CertificateVerifier(); 
        }
        
        return certificateVerifier;
    }


    /**
     * Get the chain analyser
     *
     * @return the chain analyser
     */
    public ICertificateChainAnalyzer geChainAnalyzer() {
        if (certificateChainAnalyzer == null) {
            certificateChainAnalyzer = new CertificateChainAnalyzer(); 
        }
        
        return certificateChainAnalyzer;
    }
}
