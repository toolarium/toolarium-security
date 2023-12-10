/*
 * AbstractHttpsService.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.github.toolarium.security.keystore.ISecurityManagerProvider;
import com.github.toolarium.security.keystore.SecurityManagerProviderFactory;
import com.github.toolarium.security.ssl.util.SSLUtil;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.BindException;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Simple https service
 * 
 * @author patrick
 */
public abstract class AbstractHttpsService implements Runnable {
    private static final Logger LOG = LoggerFactory.getLogger(AbstractHttpsService.class);
    
    private ISecurityManagerProvider securityManagerProvider;
    private int port;
    private SSLContext sslContext;
    private Charset encoding;
    private volatile boolean run;


    /**
     * Constructor for AbstractHttpsService
     *
     * @param securityManagerProvider the security manager provider
     * @param port the port
     * @param encoding the encoding
     * @throws GeneralSecurityException The general security exception
     */
    public AbstractHttpsService(ISecurityManagerProvider securityManagerProvider, int port, Charset encoding) throws GeneralSecurityException {
        this.run = false;
        this.securityManagerProvider = securityManagerProvider;
        this.port = port;
        
        if (encoding != null) {
            this.encoding = encoding;
        } else {
            this.encoding = Charset.forName("UTF-8");
        }
        
        if (this.securityManagerProvider == null) {
            this.securityManagerProvider = SecurityManagerProviderFactory.getInstance().getSecurityManagerProvider();
        }
        
        assertNotNull(securityManagerProvider);
        sslContext = SSLContextFactory.getInstance().createSslContext(securityManagerProvider);
        assertNotNull(sslContext);
    }

    
    /**
     * Verify if the service is running
     *
     * @return true if it is running
     */
    public boolean isRunning() {
        return run;
    }
    
    
    /**
     * @see java.lang.Runnable#run()
     */
    @Override
    public void run() {
        SSLServerSocket s  = null;
        run = true;
        
        while (isRunning()) {
            try {
                s = SSLUtil.getInstance().getSSLServerSocket(sslContext, port, true, LOG::debug);

                //String[] ciphersuites = {"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "TLS_AES_256_GCM_SHA384","TLS_AES_128_GCM_SHA256","TLS_CHACHA20_POLY1305_SHA256"};
                //s.setEnabledCipherSuites(ciphersuites);
                //s.setEnabledCipherSuites(s.getEnabledCipherSuites());
                //s.setEnabledProtocols(new String[] {"TLSv1.2" });
                
                /*String curlCiphers = "TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256 TLS_AES_128_CCM_8_SHA256 TLS_AES_128_CCM_SHA256";
                List<String> l = Arrays.asList(s.getEnabledCipherSuites());
                for (String cipher : curlCiphers.split(" ")) {
                    if (l.contains(cipher)) {
                        LOG.info("FOUND: " + cipher);
                    } else {
                        LOG.info("No FOUND: " + cipher);
                        
                    }
                }
                */
                
                SSLSocket c = (SSLSocket) s.accept();
                // TODO: c.getSession();
                
                if (LOG.isDebugEnabled()) {
                    SSLUtil.getInstance().processSocketInfo(LOG::debug, c);
                }
            
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(c.getOutputStream()));
                BufferedReader reader = new BufferedReader(new InputStreamReader(c.getInputStream()));
                List<String> headerLines = HttpUtil.getInstance().getHeaderLines(reader);
                String requestContent = HttpUtil.getInstance().readRequestContent(reader, HttpUtil.getInstance().getContentLength(headerLines));
                
                String response = createResponse(headerLines, requestContent);
                HttpUtil.getInstance().write(writer, encoding, "200 OK", "text/html", response);
                
                try {
                    writer.flush();
                } catch (SocketException e) {
                    LOG.warn("Can not flush!");
                }

                writer.close();
                reader.close();
                c.close();
            
                s.close();
                
                if (requestContent.equals("exit")) {
                    run = false;
                    break;
                }
                
            } catch (SSLException e) {
                if ("Connection reset".equals(e.getMessage()) || "An established connection was aborted by the software in your host machine".equals(e.getMessage())) {
                    LOG.debug(e.toString());
                } else {
                    LOG.warn(e.toString());
                }
                
                try {
                    if (s != null) {
                        s.close();
                    }
                } catch (IOException ex) {
                    // NOP
                }
            } catch (BindException e) {
                LOG.error(e.toString(), e);
                return;
            } catch (Exception e) {
                LOG.error(e.toString(), e);
            }
        }
        
        LOG.info("Service ended (" + run + ").");
    }


    /**
     * Create response 
     *
     * @param headerLines the header lines
     * @param requestContent the request content
     * @return the response
     */
    protected abstract String createResponse(List<String> headerLines, String requestContent);
}
