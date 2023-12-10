/*
 * SSLEchoService.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl;

import com.github.toolarium.security.keystore.ISecurityManagerProvider;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.List;


/**
 * SSL echo servier
 *  
 * @author patrick
 */
public class SSLEchoService extends AbstractHttpsService implements Runnable {
    
    
    /**
     * Constructor for SSLEchoService
     * 
     * @throws GeneralSecurityException General security exception
     */
    public SSLEchoService() throws GeneralSecurityException {
        super(null, 8888, null);
    }

    
    /**
     * Constructor for SSLEchoService
     * 
     * @param securityManagerProvider the certificate manager provider
     * @param port the port
     * @throws GeneralSecurityException General security exception
     */
    public SSLEchoService(ISecurityManagerProvider securityManagerProvider, int port) throws GeneralSecurityException {
        super(securityManagerProvider, port, null);
    }

    
    /**
     * Constructor for SSLEchoService
     * 
     * @param securityManagerProvider the certificate manager provider
     * @param port the port
     * @param encoding the encoding
     * @throws GeneralSecurityException General security exception
     */
    public SSLEchoService(ISecurityManagerProvider securityManagerProvider, int port, Charset encoding) throws GeneralSecurityException {
        super(securityManagerProvider, port, encoding);
    }
    

    /**
     * @see com.github.toolarium.security.ssl.AbstractHttpsService#createResponse(java.util.List, java.lang.String)
     */
    @Override
    protected String createResponse(List<String> headerLines, String requestContent) {
        boolean reverse = false;
        if (requestContent != null && !requestContent.isBlank() && reverse) {
            char[] a = requestContent.toCharArray();
            int n = a.length;
            for (int i = 0; i < n / 2; i++) {
                char t = a[i];
                a[i] = a[n - 1 - i];
                a[n - i - 1] = t;
            }
            
            return new String(a, 0, n);
        }
        
        return requestContent;
    }
}
