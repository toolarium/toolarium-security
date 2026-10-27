/*
 * SSLUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Date;
import java.util.function.Consumer;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;


/**
 * SSL Util
 * 
 * @author patrick
 */
public final class SSLUtil {
    private static final String NL = "\n";
    private static final String[] SECURE_PROTOCOLS = {"TLSv1.2", "TLSv1.3"};

    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static final class HOLDER {
        static final SSLUtil INSTANCE = new SSLUtil();
    }

    
    /**
     * Constructor
     */
    private SSLUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static SSLUtil getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Get SSL server socket
     *
     * @param sslContext the SSL context
     * @param port the port
     * @param propagateHostName has no effect: server names (SNI) are only sent by a client, a server socket ignores them
     * @return the SSL server socket
     * @throws GeneralSecurityException General security exception
     * @throws IOException In case of IO error
     */
    public SSLServerSocket getSSLServerSocket(SSLContext sslContext, int port, boolean propagateHostName) throws GeneralSecurityException, IOException {
        return getSSLServerSocket(sslContext, port, propagateHostName, null);
    }

    
    /**
     * Get SSL server socket
     *
     * @param sslContext the SSL context
     * @param port the port
     * @param propagateHostName has no effect: server names (SNI) are only sent by a client, a server socket ignores them
     * @param consumer the consumer
     * @return the SSL server socket
     * @throws GeneralSecurityException General security exception
     * @throws IOException In case of IO error
     */
    public SSLServerSocket getSSLServerSocket(SSLContext sslContext, int port, boolean propagateHostName, Consumer<String> consumer) throws GeneralSecurityException, IOException {
        //SSLSocketFactory sf = sslContext.getSocketFactory();
        //assertNotNull(sf);
        SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        SSLServerSocket s = (SSLServerSocket) ssf.createServerSocket(port);
        try {
            // propagateHostName has no effect: server names (SNI) are only sent by a client, a server socket ignores them

            // restrict to secure protocols: only the enabled ones of TLSv1.2 and TLSv1.3, so a JVM without TLSv1.3 and an
            // admin setting (e.g. jdk.tls.server.protocols=TLSv1.3) are respected; the handshake uses the highest common one
            String[] protocols = selectSecureProtocols(s.getEnabledProtocols());
            if (protocols.length > 0) {
                s.setEnabledProtocols(protocols);
            }

            processServerSocketInfo(consumer, s);
        } catch (Exception ex) {
            try {
                s.close();
            } catch (IOException closeEx) {
                ex.addSuppressed(closeEx);
            }
            throw ex;
        }
        return s;
    }


    /**
     * Select the secure protocols TLSv1.2 and TLSv1.3 from the enabled protocols.
     *
     * @param enabledProtocols the enabled protocols of the socket
     * @return the enabled secure protocols, empty if none of them is enabled
     */
    private String[] selectSecureProtocols(String[] enabledProtocols) {
        java.util.List<String> enabled = Arrays.asList(enabledProtocols);
        java.util.List<String> result = new java.util.ArrayList<>();
        for (String protocol : SECURE_PROTOCOLS) {
            if (enabled.contains(protocol)) {
                result.add(protocol);
            }
        }
        return result.toArray(new String[0]);
    }

    

    /**
     * Print socket information
     *
     * @param consumer the consumer
     * @param s the socket
     */
    public void processSocketInfo(Consumer<String> consumer, SSLSocket s) {
        if (consumer == null) {
            return;
        }
        
        StringBuilder msg = new StringBuilder();
        msg.append("Socket class: ").append(s.getClass()).append(NL)
        .append("   Remote address = ").append(s.getInetAddress()).append(NL)
        .append("   Remote port = ").append(s.getPort()).append(NL)
        .append("   Local socket address = ").append(s.getLocalSocketAddress()).append(NL)
        .append("   Local address = ").append(s.getLocalAddress()).append(NL)
        .append("   Local port = ").append(s.getLocalPort()).append(NL)
        .append("   Need client authentication = ").append(s.getNeedClientAuth()).append(NL)
        .append("   Enabled protocols = ").append(convertList(s.getEnabledProtocols())).append(NL)
        .append("   Enabled ciphers = ").append(convertList(s.getEnabledCipherSuites())).append(NL);

        // getSession() would start a blocking handshake, therefore only an already existing handshake session is read
        SSLSession session = s.getHandshakeSession();
        if (session != null) {
            msg.append("   Session = ").append(getSessionId(session)).append(NL)
            .append("   Session creation = ").append(new Date(session.getCreationTime())).append(NL)
            .append("   Session last access = ").append(new Date(session.getLastAccessedTime())).append(NL);
        } else {
            msg.append("   Session = no session").append(NL);
        }

        consumer.accept(msg.toString());
    }

    
    /**
     * Print server socket information
     *
     * @param consumer the consumer
     * @param s the server socket
     */
    public void processServerSocketInfo(Consumer<String> consumer, SSLServerSocket s) {
        if (consumer == null) {
            return;
        }
        
        StringBuilder msg = new StringBuilder();
        msg.append("Socket socket class: ").append(s.getClass()).append(NL)
        .append("   Socket address = ").append(s.getInetAddress()).append(NL)
        .append("   Socket port = ").append(s.getLocalPort()).append(NL)
        .append("   Need client authentication = ").append(s.getNeedClientAuth()).append(NL)
        .append("   Want client authentication = ").append(s.getWantClientAuth()).append(NL)
        .append("   Use client mode = ").append(s.getUseClientMode()).append(NL)
        .append("   Supported protocols = ").append(convertList(s.getSupportedProtocols())).append(NL)
        .append("   Enabled protocols = ").append(convertList(s.getEnabledProtocols())).append(NL)
        .append("   Supported ciphers = ").append(convertList(s.getSupportedCipherSuites())).append(NL)
        .append("   Enabled ciphers = ").append(convertList(s.getEnabledCipherSuites()));
        
        consumer.accept(msg.toString());
    }
    
    
    /**
     * Get the SSL session id
     *
     * @param session the session
     * @return the if
     */
    public String getSessionId(SSLSession session) {
        byte[] bytes = session.getId();
        if (bytes == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            String digit = Integer.toHexString(b);
            if (digit.length() < 2) {
                sb.append('0');
            }
            if (digit.length() > 2) {
                digit = digit.substring(digit.length() - 2);
            }
            sb.append(digit);
        }
        return sb.toString();
    }
    
    
    /**
     * Convert list
     *
     * @param list the list
     * @return the string
     */
    private String convertList(String[] list) {
        return Arrays.asList(list).toString().replace("[", "").replace("]", "");
    }
}
