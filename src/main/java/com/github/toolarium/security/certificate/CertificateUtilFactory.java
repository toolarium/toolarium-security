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
    private volatile ICertificateGenerator certificateGenerator;
    private volatile ICertificateConverter certificateConverter;
    private volatile ICertificateFilter certificateFilter;
    private volatile ICertificateVerifier certificateVerifier;
    private volatile ICertificateChainAnalyzer certificateChainAnalyzer;
    
    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static final class HOLDER {
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
            synchronized (this) {
                if (certificateGenerator == null) {
                    certificateGenerator = new CertificateGenerator();
                }
            }
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
            synchronized (this) {
                if (certificateConverter == null) {
                    certificateConverter = new CertificateConverter();
                }
            }
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
            synchronized (this) {
                if (certificateFilter == null) {
                    certificateFilter = new CertificateFilter();
                }
            }
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
            synchronized (this) {
                if (certificateVerifier == null) {
                    certificateVerifier = new CertificateVerifier();
                }
            }
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
            synchronized (this) {
                if (certificateChainAnalyzer == null) {
                    certificateChainAnalyzer = new CertificateChainAnalyzer();
                }
            }
        }
        return certificateChainAnalyzer;
    }
}
