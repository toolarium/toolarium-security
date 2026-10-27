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
 * An {@link SSLContext} which restricts the enabled cipher suites and protocols (TLSv1.2 and TLSv1.3) of every {@link SSLEngine}, socket and server socket
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
     * @throws IllegalArgumentException in case the cipher suites are null, empty or contain a null element
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
        private volatile SSLSocketFactory socketFactory;
        private volatile SSLServerSocketFactory serverSocketFactory;


        /**
         * Constructor for RestrictedSSLContextSpi
         *
         * @param delegate the SSL context to wrap
         * @param cipherSuites the cipher suites to enable
         */
        RestrictedSSLContextSpi(SSLContext delegate, String[] cipherSuites) {
            this.delegate = delegate;
            this.cipherSuites = RestrictionSupport.validateCipherSuites(cipherSuites);
        }


        /**
         * @see javax.net.ssl.SSLContextSpi#engineInit(javax.net.ssl.KeyManager[], javax.net.ssl.TrustManager[], java.security.SecureRandom)
         */
        @Override
        protected void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) throws KeyManagementException {
            delegate.init(keyManagers, trustManagers, secureRandom);

            // the factories of the previous initialisation are not used anymore
            synchronized (this) {
                socketFactory = null;
                serverSocketFactory = null;
            }
        }


        /**
         * The factory is created once and reused, so connections can be reused (e.g. keep alive of HttpsURLConnection).
         *
         * @see javax.net.ssl.SSLContextSpi#engineGetSocketFactory()
         */
        @Override
        protected SSLSocketFactory engineGetSocketFactory() {
            SSLSocketFactory result = socketFactory;
            if (result == null) {
                synchronized (this) {
                    result = socketFactory;
                    if (result == null) {
                        result = new RestrictedSSLSocketFactory(delegate.getSocketFactory(), cipherSuites);
                        socketFactory = result;
                    }
                }
            }

            return result;
        }


        /**
         * The factory is created once and reused.
         *
         * @see javax.net.ssl.SSLContextSpi#engineGetServerSocketFactory()
         */
        @Override
        protected SSLServerSocketFactory engineGetServerSocketFactory() {
            SSLServerSocketFactory result = serverSocketFactory;
            if (result == null) {
                synchronized (this) {
                    result = serverSocketFactory;
                    if (result == null) {
                        result = new RestrictedSSLServerSocketFactory(delegate.getServerSocketFactory(), cipherSuites);
                        serverSocketFactory = result;
                    }
                }
            }

            return result;
        }


        /**
         * @see javax.net.ssl.SSLContextSpi#engineCreateSSLEngine()
         */
        @Override
        protected SSLEngine engineCreateSSLEngine() {
            return restrict(delegate.createSSLEngine());
        }


        /**
         * @see javax.net.ssl.SSLContextSpi#engineCreateSSLEngine(java.lang.String, int)
         */
        @Override
        protected SSLEngine engineCreateSSLEngine(String host, int port) {
            return restrict(delegate.createSSLEngine(host, port));
        }


        /**
         * Restrict the enabled cipher suites and protocols of the engine
         *
         * @param engine the engine
         * @return the engine
         */
        private SSLEngine restrict(SSLEngine engine) {
            engine.setEnabledCipherSuites(cipherSuites.clone());
            String[] protocols = RestrictionSupport.selectProtocols(engine.getSupportedProtocols());
            if (protocols.length > 0) {
                engine.setEnabledProtocols(protocols);
            }
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
            String[] protocols = RestrictionSupport.selectProtocols(delegate.getSupportedSSLParameters().getProtocols());
            if (protocols.length > 0) {
                parameters.setProtocols(protocols);
            }
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
