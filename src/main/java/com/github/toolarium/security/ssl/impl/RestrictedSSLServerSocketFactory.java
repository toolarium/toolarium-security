/*
 * RestrictedSSLServerSocketFactory.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl.impl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;


/**
 * An {@link SSLServerSocketFactory} which restricts the enabled cipher suites and protocols (TLSv1.2 and TLSv1.3) of every created server socket.
 *
 * @author patrick
 */
public class RestrictedSSLServerSocketFactory extends SSLServerSocketFactory {
    private final SSLServerSocketFactory delegate;
    private final String[] cipherSuites;


    /**
     * Constructor for RestrictedSSLServerSocketFactory
     *
     * @param delegate the server socket factory to wrap
     * @param cipherSuites the cipher suites to enable, they must be supported by the delegate
     * @throws IllegalArgumentException in case the cipher suites are null, empty or contain a null element
     */
    public RestrictedSSLServerSocketFactory(SSLServerSocketFactory delegate, String[] cipherSuites) {
        this.delegate = delegate;
        this.cipherSuites = RestrictionSupport.validateCipherSuites(cipherSuites);
    }


    /**
     * @see javax.net.ssl.SSLServerSocketFactory#getDefaultCipherSuites()
     */
    @Override
    public String[] getDefaultCipherSuites() {
        return cipherSuites.clone();
    }


    /**
     * @see javax.net.ssl.SSLServerSocketFactory#getSupportedCipherSuites()
     */
    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }


    /**
     * @see javax.net.ServerSocketFactory#createServerSocket()
     */
    @Override
    public ServerSocket createServerSocket() throws IOException {
        return restrict(delegate.createServerSocket());
    }


    /**
     * @see javax.net.ServerSocketFactory#createServerSocket(int)
     */
    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        return restrict(delegate.createServerSocket(port));
    }


    /**
     * @see javax.net.ServerSocketFactory#createServerSocket(int, int)
     */
    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        return restrict(delegate.createServerSocket(port, backlog));
    }


    /**
     * @see javax.net.ServerSocketFactory#createServerSocket(int, int, java.net.InetAddress)
     */
    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
        return restrict(delegate.createServerSocket(port, backlog, ifAddress));
    }


    /**
     * Restrict the enabled cipher suites and protocols of the server socket. In case the restriction fails the server socket is closed.
     *
     * @param serverSocket the server socket
     * @return the server socket
     */
    private ServerSocket restrict(ServerSocket serverSocket) {
        if (serverSocket instanceof SSLServerSocket) {
            SSLServerSocket sslServerSocket = (SSLServerSocket) serverSocket;
            try {
                sslServerSocket.setEnabledCipherSuites(cipherSuites.clone());
                String[] protocols = RestrictionSupport.selectProtocols(sslServerSocket.getSupportedProtocols());
                if (protocols.length > 0) {
                    sslServerSocket.setEnabledProtocols(protocols);
                }
            } catch (RuntimeException ex) {
                try {
                    sslServerSocket.close();
                } catch (IOException closeEx) {
                    ex.addSuppressed(closeEx);
                }
                throw ex;
            }
        }
        return serverSocket;
    }
}
