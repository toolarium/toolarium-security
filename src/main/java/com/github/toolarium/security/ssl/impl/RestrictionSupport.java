/*
 * RestrictionSupport.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Package internal support for the restricted SSL classes: validates the cipher suites and selects the
 * protocols to enable.
 *
 * @author patrick
 */
final class RestrictionSupport {
    private static final Logger LOG = LoggerFactory.getLogger(RestrictionSupport.class);
    private static final String[] ALLOWED_PROTOCOLS = {"TLSv1.2", "TLSv1.3"};
    private static final AtomicBoolean NO_PROTOCOL_WARNING_LOGGED = new AtomicBoolean(false);


    /**
     * Constructor for RestrictionSupport
     */
    private RestrictionSupport() {
        // NOP
    }


    /**
     * Validate the cipher suites and return a copy of them.
     *
     * @param cipherSuites the cipher suites
     * @return a copy of the cipher suites
     * @throws IllegalArgumentException in case the cipher suites are null, empty or contain a null element
     */
    static String[] validateCipherSuites(String[] cipherSuites) {
        if (cipherSuites == null || cipherSuites.length == 0) {
            throw new IllegalArgumentException("The cipher suites must not be null or empty!");
        }

        String[] result = cipherSuites.clone();
        for (String cipherSuite : result) {
            if (cipherSuite == null) {
                throw new IllegalArgumentException("The cipher suites must not contain a null element!");
            }
        }
        return result;
    }


    /**
     * Select the allowed protocols (TLSv1.2 and TLSv1.3) which are contained in the given supported protocols.
     * In case none of them is supported an empty array is returned and a warning is logged once.
     *
     * @param supportedProtocols the supported protocols
     * @return the protocols to enable or an empty array to keep the defaults
     */
    static String[] selectProtocols(String[] supportedProtocols) {
        List<String> result = new ArrayList<>();
        if (supportedProtocols != null) {
            List<String> supported = Arrays.asList(supportedProtocols);
            for (String protocol : ALLOWED_PROTOCOLS) {
                if (supported.contains(protocol)) {
                    result.add(protocol);
                }
            }
        }

        if (result.isEmpty() && NO_PROTOCOL_WARNING_LOGGED.compareAndSet(false, true)) {
            LOG.warn("None of the protocols {} is supported, the default protocols are kept.", Arrays.toString(ALLOWED_PROTOCOLS));
        }
        return result.toArray(new String[result.size()]);
    }
}
