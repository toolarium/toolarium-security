/*
 * SSLContextFactoryTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.github.toolarium.security.keystore.ISecurityManagerProvider;
import com.github.toolarium.security.keystore.SecurityManagerProviderFactory;
import com.github.toolarium.security.keystore.util.KeyStoreUtil;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the {@link SSLContextFactory}.
 * 
 * @author patrick
 */
public class SSLContextFactoryTest {
    private static final Logger LOG = LoggerFactory.getLogger(SSLContextFactoryTest.class);

    
    /**
     * Test the key store configuration. Test on command line:
     * <code>
     * curl -d '{"key1":"value1", "key2":"value2"}' -H "Content-Type: application/json" -k -s -X POST "https://localhost:8080/"
     * curl -d 'exit' -H "Content-Type: application/json" -k -s -X POST "https://localhost:8080/"
     * </code>
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    //@Test()
    public void manualTest() throws GeneralSecurityException, IOException {
        // create self signed certificate
        ISecurityManagerProvider securityManagerProvider = SecurityManagerProviderFactory.getInstance().getSecurityManagerProvider("toolarium", "changit");
        assertNotNull(securityManagerProvider);
        
        int port = 8080;
        SSLEchoService sslEchoService = new SSLEchoService(securityManagerProvider, port);
        Thread thread = new Thread(sslEchoService);
        thread.setDaemon(true);
        thread.start();
        try {
            Thread.sleep(100L);
        } catch (InterruptedException e) {
            // NOP
        }

        while (sslEchoService.isRunning()) {
            try {
                Thread.sleep(100L);
            } catch (InterruptedException e) {
                // NOP
            }
        }
    }


    /**
     * Test and accept all certificates
     *
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     * @throws InterruptedException In case of an interrupt error
     */
    @Test
    public void httpClientTestAcceptAllCertificates() throws GeneralSecurityException, IOException, InterruptedException {
        // create self signed certificate
        ISecurityManagerProvider securityManagerProvider = SecurityManagerProviderFactory.getInstance().getSecurityManagerProvider("toolarium", "changit");
        assertNotNull(securityManagerProvider);
        final int testPort = 8081;

        // start echo service
        SSLEchoService sslEchoService = startSSLEchoService(securityManagerProvider, testPort);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, KeyStoreUtil.getInstance().getTrustAllCertificateManager(), SecureRandom.getInstanceStrong()); 

        runTestAndEndup(sslContext, testPort, sslEchoService);
    }

    
    /**
     * Test and accept self signed certificate
     *
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     * @throws InterruptedException In case of an interrupt error
     */
    @Test
    public void httpClientTestAcceptSelfSignedCertificate() throws GeneralSecurityException, IOException, InterruptedException {
        // create self signed certificate
        ISecurityManagerProvider securityManagerProvider = SecurityManagerProviderFactory.getInstance().getSecurityManagerProvider("toolarium", "changit");
        assertNotNull(securityManagerProvider);
        final int testPort = 8082;

        // start echo service
        SSLEchoService sslEchoService = startSSLEchoService(securityManagerProvider, testPort);
 
        SSLContext sslContext = SSLContext.getInstance("TLS");
        
        // use trust manager with added self-signed certificate
        sslContext.init(securityManagerProvider.getKeyManagers(), securityManagerProvider.getTrustManagers(), SecureRandom.getInstanceStrong()); 

        runTestAndEndup(sslContext, testPort, sslEchoService);
    }

    
    /**
     * Test and accept self signed certificate
     *
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     * @throws InterruptedException In case of an interrupt error
     */
    @Test
    public void httpClientTest() throws GeneralSecurityException, IOException, InterruptedException {
        // create self signed certificate
        ISecurityManagerProvider securityManagerProvider = SecurityManagerProviderFactory.getInstance().getSecurityManagerProvider("toolarium", "changit");
        assertNotNull(securityManagerProvider);
        final int testPort = 8083;

        // start echo service
        SSLEchoService sslEchoService = startSSLEchoService(securityManagerProvider, testPort);
        
        // get ssl context from factory
        SSLContext sslContext = SSLContextFactory.getInstance().createSslContext(securityManagerProvider);
        
        runTestAndEndup(sslContext, testPort, sslEchoService);
    }


    /**
     * Run test and endup
     *
     * @param sslContext the ssl context
     * @param testPort the test port
     * @param sslEchoService the service
     * @throws IOException In case of an I/O error
     * @throws InterruptedException In case of an interrupt error
     */
    protected void runTestAndEndup(SSLContext sslContext, int testPort, SSLEchoService sslEchoService) throws IOException, InterruptedException {
        // prepare client
        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .sslContext(sslContext)
                .build();
        
        // test echo service
        String requestText = "Test of java SSL write";
        HttpRequest request = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(requestText))
                .uri(URI.create("https://localhost:" + testPort))
                .build();
        
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        HttpHeaders headers = response.headers();
        headers.map().forEach((k, v) -> LOG.debug(k + ":" + v));
        LOG.debug("Response " + response.statusCode() + ":\n" + response.body());
        assertEquals(requestText, response.body());
        
        Thread.sleep(100L);

        // send stop server command: exit
        request = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString("exit"))
                .uri(URI.create("https://localhost:" + testPort))
                .build();

        response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        Thread.sleep(10L);
        assertFalse(sslEchoService.isRunning());
        
    }


    /**
     * Start SSL echo service
     *
     * @param securityManagerProvider the security manager provider
     * @param testPort the test port
     * @return the service
     * @throws GeneralSecurityException in case of error
     */
    protected SSLEchoService startSSLEchoService(ISecurityManagerProvider securityManagerProvider, int testPort) throws GeneralSecurityException {
        // start echo service
        SSLEchoService sslEchoService = new SSLEchoService(securityManagerProvider, testPort);
        Thread thread = new Thread(sslEchoService);
        thread.setDaemon(true);
        thread.start();
        
        return sslEchoService;
    }
}
