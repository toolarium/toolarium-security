/*
 * RestrictedSSLSocketFactory.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl.impl;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


/**
 * An {@link SSLSocketFactory} which restricts the enabled cipher suites of every created socket.
 *
 * @author patrick
 */
public class RestrictedSSLSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory delegate;
    private final String[] cipherSuites;


    /**
     * Constructor for RestrictedSSLSocketFactory
     *
     * @param delegate the socket factory to wrap
     * @param cipherSuites the cipher suites to enable, they must be supported by the delegate
     */
    public RestrictedSSLSocketFactory(SSLSocketFactory delegate, String[] cipherSuites) {
        this.delegate = delegate;
        this.cipherSuites = cipherSuites.clone();
    }


    /**
     * @see javax.net.ssl.SSLSocketFactory#getDefaultCipherSuites()
     */
    @Override
    public String[] getDefaultCipherSuites() {
        return cipherSuites.clone();
    }


    /**
     * @see javax.net.ssl.SSLSocketFactory#getSupportedCipherSuites()
     */
    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }


    /**
     * @see javax.net.SocketFactory#createSocket()
     */
    @Override
    public Socket createSocket() throws IOException {
        return restrict(delegate.createSocket());
    }


    /**
     * @see javax.net.ssl.SSLSocketFactory#createSocket(java.net.Socket, java.lang.String, int, boolean)
     */
    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return restrict(delegate.createSocket(socket, host, port, autoClose));
    }


    /**
     * @see javax.net.ssl.SSLSocketFactory#createSocket(java.net.Socket, java.io.InputStream, boolean)
     */
    @Override
    public Socket createSocket(Socket socket, InputStream consumed, boolean autoClose) throws IOException {
        return restrict(delegate.createSocket(socket, consumed, autoClose));
    }


    /**
     * @see javax.net.SocketFactory#createSocket(java.lang.String, int)
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return restrict(delegate.createSocket(host, port));
    }


    /**
     * @see javax.net.SocketFactory#createSocket(java.lang.String, int, java.net.InetAddress, int)
     */
    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return restrict(delegate.createSocket(host, port, localHost, localPort));
    }


    /**
     * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int)
     */
    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return restrict(delegate.createSocket(host, port));
    }


    /**
     * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int, java.net.InetAddress, int)
     */
    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return restrict(delegate.createSocket(address, port, localAddress, localPort));
    }


    /**
     * Restrict the enabled cipher suites of the socket
     *
     * @param socket the socket
     * @return the socket
     */
    private Socket restrict(Socket socket) {
        if (socket instanceof SSLSocket) {
            ((SSLSocket) socket).setEnabledCipherSuites(cipherSuites.clone());
        }
        return socket;
    }
}
