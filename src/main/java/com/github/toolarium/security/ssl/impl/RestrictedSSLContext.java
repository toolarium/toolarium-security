/*
 * RestrictedSSLContext.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl.impl;

import java.security.KeyManagementException;
import java.security.SecureRandom;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;


/**
 * An {@link SSLContext} which restricts the enabled cipher suites of every {@link SSLEngine}, socket and server socket
 * it creates, as well as of its default {@link SSLParameters}. All other calls are delegated to the wrapped context.
 *
 * @author patrick
 */
public class RestrictedSSLContext extends SSLContext {

    /**
     * Constructor for RestrictedSSLContext
     *
     * @param delegate the initialized SSL context to wrap
     * @param cipherSuites the cipher suites to enable, they must be supported by the delegate
     */
    public RestrictedSSLContext(SSLContext delegate, String[] cipherSuites) {
        super(new RestrictedSSLContextSpi(delegate, cipherSuites), delegate.getProvider(), delegate.getProtocol());
    }


    /**
     * The SSL context SPI which delegates to the wrapped context and restricts the cipher suites.
     *
     * @author patrick
     */
    private static final class RestrictedSSLContextSpi extends SSLContextSpi {
        private final SSLContext delegate;
        private final String[] cipherSuites;


        /**
         * Constructor for RestrictedSSLContextSpi
         *
         * @param delegate the SSL context to wrap
         * @param cipherSuites the cipher suites to enable
         */
        RestrictedSSLContextSpi(SSLContext delegate, String[] cipherSuites) {
            this.delegate = delegate;
            this.cipherSuites = cipherSuites.clone();
        }


        /**
         * @see javax.net.ssl.SSLContextSpi#engineInit(javax.net.ssl.KeyManager[], javax.net.ssl.TrustManager[], java.security.SecureRandom)
         */
        @Override
        protected void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) throws KeyManagementException {
            delegate.init(keyManagers, trustManagers, secureRandom);
        }


        /**
         * @see javax.net.ssl.SSLContextSpi#engineGetSocketFactory()
         */
        @Override
        protected SSLSocketFactory engineGetSocketFactory() {
            return new RestrictedSSLSocketFactory(delegate.getSocketFactory(), cipherSuites);
        }


        /**
         * @see javax.net.ssl.SSLContextSpi#engineGetServerSocketFactory()
         */
        @Override
        protected SSLServerSocketFactory engineGetServerSocketFactory() {
            return new RestrictedSSLServerSocketFactory(delegate.getServerSocketFactory(), cipherSuites);
        }


        /**
         * @see javax.net.ssl.SSLContextSpi#engineCreateSSLEngine()
         */
        @Override
        protected SSLEngine engineCreateSSLEngine() {
            SSLEngine engine = delegate.createSSLEngine();
            engine.setEnabledCipherSuites(cipherSuites.clone());
            return engine;
        }


        /**
         * @see javax.net.ssl.SSLContextSpi#engineCreateSSLEngine(java.lang.String, int)
         */
        @Override
        protected SSLEngine engineCreateSSLEngine(String host, int port) {
            SSLEngine engine = delegate.createSSLEngine(host, port);
            engine.setEnabledCipherSuites(cipherSuites.clone());
            return engine;
        }


        /**
         * @see javax.net.ssl.SSLContextSpi#engineGetServerSessionContext()
         */
        @Override
        protected SSLSessionContext engineGetServerSessionContext() {
            return delegate.getServerSessionContext();
        }


        /**
         * @see javax.net.ssl.SSLContextSpi#engineGetClientSessionContext()
         */
        @Override
        protected SSLSessionContext engineGetClientSessionContext() {
            return delegate.getClientSessionContext();
        }


        /**
         * @see javax.net.ssl.SSLContextSpi#engineGetDefaultSSLParameters()
         */
        @Override
        protected SSLParameters engineGetDefaultSSLParameters() {
            // e.g. the java HttpClient applies the default parameters to its engines
            SSLParameters parameters = delegate.getDefaultSSLParameters();
            parameters.setCipherSuites(cipherSuites.clone());
            return parameters;
        }


        /**
         * @see javax.net.ssl.SSLContextSpi#engineGetSupportedSSLParameters()
         */
        @Override
        protected SSLParameters engineGetSupportedSSLParameters() {
            return delegate.getSupportedSSLParameters();
        }
    }
}
