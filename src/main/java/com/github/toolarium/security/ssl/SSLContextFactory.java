/*
 * SSLContextFactory.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl;

import com.github.toolarium.security.keystore.ISecurityManagerProvider;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Defines the SSL context factory.
 *
 * <p>Use {@link #createSslContext(ISecurityManagerProvider, String...)} to restrict the
 * enabled cipher suites. When no cipher suites are supplied the JVM defaults apply.
 * Because Java's {@link SSLContext} does not support setting a global cipher suite list,
 * call {@link #applyCipherSuites(SSLEngine, String...)} on every {@link SSLEngine} or
 * {@link javax.net.ssl.SSLSocket} created from the context to enforce the restriction.</p>
 *
 * @author patrick
 */
public final class SSLContextFactory {
    private static final Logger LOG = LoggerFactory.getLogger(SSLContextFactory.class);
    private final SecureRandom secureRandom;

    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static final class HOLDER {
        static final SSLContextFactory INSTANCE = new SSLContextFactory();
    }


    /**
     * Constructor
     */
    private SSLContextFactory() {
        secureRandom = new SecureRandom();
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static SSLContextFactory getInstance() {
        return HOLDER.INSTANCE;
    }


    /**
     * Create an SSL context using the JVM default cipher suites.
     *
     * @param securityManagerProvider the security manager provider
     * @return the SSL context
     * @throws GeneralSecurityException if the security key access was not successful
     */
    public SSLContext createSslContext(ISecurityManagerProvider securityManagerProvider) throws GeneralSecurityException {
        return createSslContext(securityManagerProvider, (String[]) null);
    }


    /**
     * Create an SSL context.
     *
     * <p>When {@code allowedCipherSuites} is non-empty the supplied suites are validated
     * against those supported by the context. Unsupported suites are logged and ignored.
     * Call {@link #applyCipherSuites(SSLEngine, String...)} with the same list on every
     * {@link SSLEngine} or {@link javax.net.ssl.SSLSocket} created from the returned context
     * to enforce the restriction, as {@link SSLContext} itself does not apply it globally.</p>
     *
     * @param securityManagerProvider the security manager provider
     * @param allowedCipherSuites the cipher suites to allow, or empty/null for JVM defaults
     * @return the SSL context
     * @throws GeneralSecurityException if the security key access was not successful
     */
    public SSLContext createSslContext(ISecurityManagerProvider securityManagerProvider, String... allowedCipherSuites) throws GeneralSecurityException {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(securityManagerProvider.getKeyManagers(), securityManagerProvider.getTrustManagers(), secureRandom);

        if (allowedCipherSuites != null && allowedCipherSuites.length > 0) {
            applyCipherSuites(sslContext.createSSLEngine(), allowedCipherSuites);
        }

        return sslContext;
    }


    /**
     * Apply the given cipher suites to an {@link SSLEngine}, restricting it to only those
     * suites that are both requested and supported. Unsupported suites are logged and skipped.
     * If {@code allowedCipherSuites} is empty the engine's enabled suites are left unchanged.
     *
     * @param engine the SSL engine to configure
     * @param allowedCipherSuites the cipher suites to enable
     */
    public void applyCipherSuites(SSLEngine engine, String... allowedCipherSuites) {
        if (engine == null || allowedCipherSuites == null || allowedCipherSuites.length == 0) {
            return;
        }

        java.util.Set<String> supported = new java.util.HashSet<>(java.util.Arrays.asList(engine.getSupportedCipherSuites()));
        java.util.List<String> enabled = new java.util.ArrayList<>();
        for (String suite : allowedCipherSuites) {
            if (supported.contains(suite)) {
                enabled.add(suite);
            } else {
                LOG.warn("Cipher suite not supported by JVM, skipping: " + suite);
            }
        }

        if (!enabled.isEmpty()) {
            engine.setEnabledCipherSuites(enabled.toArray(new String[0]));
        }
    }
}
