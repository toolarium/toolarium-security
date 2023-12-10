/*
 * SSLContextFactory.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl;

import com.github.toolarium.security.keystore.ISecurityManagerProvider;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.net.ssl.SSLContext;


/**
 * Defines the SSL context factory.
 *  
 * @author patrick
 */
public final class SSLContextFactory {

    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final SSLContextFactory INSTANCE = new SSLContextFactory();
    }

    
    /**
     * Constructor
     */
    private SSLContextFactory() {
        // NOP
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
     * Create an SSL context
     * 
     * @param securityManagerProvider the security manager provider
     * @return The SSL context
     * @throws GeneralSecurityException If the security key axxess was not successful
     */
    public SSLContext createSslContext(ISecurityManagerProvider securityManagerProvider) throws GeneralSecurityException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(securityManagerProvider.getKeyManagers(), securityManagerProvider.getTrustManagers(), SecureRandom.getInstanceStrong());
        return sslContext;
    }
}
