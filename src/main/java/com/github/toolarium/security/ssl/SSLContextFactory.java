/*
 * SSLContextFactory.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl;

import com.github.toolarium.security.keystore.ISecurityManagerProvider;
import com.github.toolarium.security.ssl.impl.RestrictedSSLContext;
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
 * enabled cipher suites: the returned context applies them to every {@link SSLEngine} and socket
 * it creates. When no cipher suites are supplied the JVM defaults apply.</p>
 *
 * @author patrick
 */
public final class SSLContextFactory {
    /**
     * A curated allowlist of strong cipher suites for TLS 1.3 and TLS 1.2.
     *
     * <p>TLS 1.3 suites are listed first (preferred); the JVM negotiates 1.3 automatically
     * when both peers support it and falls back to 1.2 otherwise.
     * All TLS 1.2 suites provide forward secrecy (ECDHE/DHE) and authenticated encryption
     * (GCM). RC4, NULL, EXPORT, and CBC-based suites are intentionally excluded.</p>
     *
     * @deprecated the array can be modified by any code in the JVM, use {@link #getRecommendedCipherSuites()}
     *             which returns a copy
     */
    @Deprecated
    public static final String[] RECOMMENDED_CIPHER_SUITES = {
        // TLS 1.3
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        // TLS 1.2
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
    };

    private static final String[] DEFAULT_RECOMMENDED_CIPHER_SUITES = RECOMMENDED_CIPHER_SUITES.clone();
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
     * Get a curated allowlist of strong cipher suites for TLS 1.3 and TLS 1.2.
     *
     * <p>TLS 1.3 suites are listed first (preferred); the JVM negotiates 1.3 automatically
     * when both peers support it and falls back to 1.2 otherwise.
     * All TLS 1.2 suites provide forward secrecy (ECDHE/DHE) and authenticated encryption
     * (GCM). RC4, NULL, EXPORT, and CBC-based suites are intentionally excluded.</p>
     *
     * <p>Pass them to {@link #createSslContext(ISecurityManagerProvider, String...)}:</p>
     * <pre>
     *     SSLContextFactory factory = SSLContextFactory.getInstance();
     *     SSLContext ctx = factory.createSslContext(provider, factory.getRecommendedCipherSuites());
     * </pre>
     *
     * @return a copy of the recommended cipher suites
     */
    public String[] getRecommendedCipherSuites() {
        return DEFAULT_RECOMMENDED_CIPHER_SUITES.clone();
    }


    /**
     * Create an SSL context using the JVM default cipher suites.
     *
     * <p><strong>Note:</strong> JVM defaults may include weak cipher suites. For production
     * use, pass {@link #getRecommendedCipherSuites()} to
     * {@link #createSslContext(ISecurityManagerProvider, String...)}.</p>
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
     * The returned context ({@link RestrictedSSLContext}) enables only the supported suites on every
     * {@link SSLEngine}, {@link javax.net.ssl.SSLSocket} and {@link javax.net.ssl.SSLServerSocket}
     * it creates and in its default {@link javax.net.ssl.SSLParameters}. If none of the suites is
     * supported, a warning is logged and the JVM defaults apply.</p>
     *
     * @param securityManagerProvider the security manager provider
     * @param allowedCipherSuites the cipher suites to allow, or empty/null for JVM defaults
     * @return the SSL context
     * @throws GeneralSecurityException if the security key access was not successful
     */
    public SSLContext createSslContext(ISecurityManagerProvider securityManagerProvider, String... allowedCipherSuites) throws GeneralSecurityException {
        // "TLS" lets the JVM negotiate TLS 1.3 (preferred) or TLS 1.2 as fallback.
        // TLS 1.0/1.1 are disabled by default in JDK 8u291+ and JDK 11+.
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(securityManagerProvider.getKeyManagers(), securityManagerProvider.getTrustManagers(), secureRandom);

        if (allowedCipherSuites != null && allowedCipherSuites.length > 0) {
            String[] cipherSuites = filterSupportedCipherSuites(sslContext.createSSLEngine(), allowedCipherSuites);
            if (cipherSuites.length > 0) {
                return new RestrictedSSLContext(sslContext, cipherSuites);
            }

            LOG.warn("None of the allowed cipher suites is supported by the JVM, the JVM default cipher suites are used.");
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

        String[] enabled = filterSupportedCipherSuites(engine, allowedCipherSuites);
        if (enabled.length > 0) {
            engine.setEnabledCipherSuites(enabled);
        }
    }


    /**
     * Filter the cipher suites which are supported by the given {@link SSLEngine}. Unsupported suites are logged and skipped.
     *
     * @param engine the SSL engine
     * @param allowedCipherSuites the cipher suites to filter
     * @return the supported cipher suites
     */
    private String[] filterSupportedCipherSuites(SSLEngine engine, String... allowedCipherSuites) {
        java.util.Set<String> supported = new java.util.HashSet<>(java.util.Arrays.asList(engine.getSupportedCipherSuites()));
        java.util.List<String> enabled = new java.util.ArrayList<>();
        for (String suite : allowedCipherSuites) {
            if (supported.contains(suite)) {
                enabled.add(suite);
            } else {
                LOG.warn("Cipher suite not supported by JVM, skipping: " + suite);
            }
        }
        return enabled.toArray(new String[0]);
    }
}
