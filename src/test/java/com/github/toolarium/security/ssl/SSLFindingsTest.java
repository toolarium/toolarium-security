/*
 * SSLFindingsTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.ssl.impl.RestrictedSSLContext;
import com.github.toolarium.security.ssl.impl.RestrictedSSLServerSocketFactory;
import com.github.toolarium.security.ssl.impl.RestrictedSSLSocketFactory;
import com.github.toolarium.security.ssl.util.SSLUtil;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.Test;


/**
 * Test the SSL audit findings N100, N104, N105 and N106.
 *
 * @author patrick
 */
public class SSLFindingsTest {
    private static final List<String> ALLOWED_PROTOCOLS = Arrays.asList("TLSv1.2", "TLSv1.3");


    /**
     * Test that a restricted context enables only TLSv1.2 and TLSv1.3 (N100).
     *
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an IO error
     */
    @Test
    public void testRestrictedContextProtocols() throws GeneralSecurityException, IOException {
        SSLContext sslContext = new RestrictedSSLContext(createBaseContext(), getSupportedCipherSuites());
        assertAllowedProtocols(sslContext.createSSLEngine().getEnabledProtocols());
        assertAllowedProtocols(sslContext.createSSLEngine("localhost", 443).getEnabledProtocols());
        assertAllowedProtocols(sslContext.getDefaultSSLParameters().getProtocols());

        try (SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket()) {
            assertAllowedProtocols(socket.getEnabledProtocols());
        }

        try (SSLServerSocket serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(0)) {
            assertAllowedProtocols(serverSocket.getEnabledProtocols());
        }
    }


    /**
     * Test that a restricted context returns the same socket factories on every call (N107).
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testRestrictedContextReusesFactories() throws GeneralSecurityException {
        SSLContext sslContext = new RestrictedSSLContext(createBaseContext(), getSupportedCipherSuites());
        assertTrue(sslContext.getSocketFactory() == sslContext.getSocketFactory());
        assertTrue(sslContext.getServerSocketFactory() == sslContext.getServerSocketFactory());
    }


    /**
     * Test that the socket info of an unconnected socket and an unbound server socket can be processed (N104).
     *
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of an IO error
     */
    @Test
    public void testProcessSocketInfoUnconnected() throws GeneralSecurityException, IOException {
        SSLContext sslContext = createBaseContext();
        StringBuilder output = new StringBuilder();
        try (SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket()) {
            SSLUtil.getInstance().processSocketInfo(output::append, socket);
        }
        assertTrue(output.toString().contains("no session"));

        StringBuilder serverOutput = new StringBuilder();
        try (SSLServerSocket serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket()) {
            SSLUtil.getInstance().processServerSocketInfo(serverOutput::append, serverSocket);
        }
        assertFalse(serverOutput.toString().isEmpty());
    }


    /**
     * Test that the constructors reject null, empty or null containing cipher suites (N105).
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testInvalidCipherSuites() throws GeneralSecurityException {
        SSLContext sslContext = createBaseContext();
        List<String[]> invalidCipherSuites = Arrays.asList(null, new String[0], new String[] {null});
        for (String[] cipherSuites : invalidCipherSuites) {
            assertThrows(IllegalArgumentException.class, () -> new RestrictedSSLContext(sslContext, cipherSuites));
            assertThrows(IllegalArgumentException.class, () -> new RestrictedSSLSocketFactory(sslContext.getSocketFactory(), cipherSuites));
            assertThrows(IllegalArgumentException.class, () -> new RestrictedSSLServerSocketFactory(sslContext.getServerSocketFactory(), cipherSuites));
        }
    }


    /**
     * Test that the server socket is closed in case the restriction fails (N106).
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testServerSocketClosedOnRestrictionFailure() throws GeneralSecurityException {
        RecordingServerSocketFactory recordingFactory = new RecordingServerSocketFactory(createBaseContext().getServerSocketFactory());
        RestrictedSSLServerSocketFactory factory = new RestrictedSSLServerSocketFactory(recordingFactory, new String[] {"UNSUPPORTED_CIPHER_SUITE"});
        assertThrows(IllegalArgumentException.class, () -> factory.createServerSocket(0));
        assertNotNull(recordingFactory.getLastServerSocket());
        assertTrue(recordingFactory.getLastServerSocket().isClosed());
    }


    /**
     * Create an initialized base SSL context
     *
     * @return the SSL context
     * @throws GeneralSecurityException in case of error
     */
    private SSLContext createBaseContext() throws GeneralSecurityException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        return sslContext;
    }


    /**
     * Get the cipher suites to use which are supported by the JVM
     *
     * @return the cipher suites
     * @throws GeneralSecurityException in case of error
     */
    private String[] getSupportedCipherSuites() throws GeneralSecurityException {
        List<String> supported = Arrays.asList(createBaseContext().createSSLEngine().getSupportedCipherSuites());
        String[] result = SSLContextFactory.getInstance().getRecommendedCipherSuites();
        result = Arrays.stream(result).filter(supported::contains).toArray(String[]::new);
        assertTrue(result.length > 0);
        return result;
    }


    /**
     * Assert that only allowed protocols are enabled
     *
     * @param protocols the enabled protocols
     */
    private void assertAllowedProtocols(String[] protocols) {
        assertNotNull(protocols);
        assertTrue(protocols.length > 0);
        for (String protocol : protocols) {
            assertTrue(ALLOWED_PROTOCOLS.contains(protocol), "Unexpected protocol: " + protocol);
        }
    }


    /**
     * Server socket factory which records the last created server socket.
     *
     * @author patrick
     */
    private static final class RecordingServerSocketFactory extends SSLServerSocketFactory {
        private final SSLServerSocketFactory delegate;
        private volatile ServerSocket lastServerSocket;


        /**
         * Constructor for RecordingServerSocketFactory
         *
         * @param delegate the delegate
         */
        RecordingServerSocketFactory(SSLServerSocketFactory delegate) {
            this.delegate = delegate;
        }


        /**
         * Get the last created server socket
         *
         * @return the last created server socket
         */
        ServerSocket getLastServerSocket() {
            return lastServerSocket;
        }


        /**
         * @see javax.net.ssl.SSLServerSocketFactory#getDefaultCipherSuites()
         */
        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }


        /**
         * @see javax.net.ssl.SSLServerSocketFactory#getSupportedCipherSuites()
         */
        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }


        /**
         * @see javax.net.ServerSocketFactory#createServerSocket(int)
         */
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            lastServerSocket = delegate.createServerSocket(port);
            return lastServerSocket;
        }


        /**
         * @see javax.net.ServerSocketFactory#createServerSocket(int, int)
         */
        @Override
        public ServerSocket createServerSocket(int port, int backlog) throws IOException {
            lastServerSocket = delegate.createServerSocket(port, backlog);
            return lastServerSocket;
        }


        /**
         * @see javax.net.ServerSocketFactory#createServerSocket(int, int, java.net.InetAddress)
         */
        @Override
        public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
            lastServerSocket = delegate.createServerSocket(port, backlog, ifAddress);
            return lastServerSocket;
        }
    }
}
