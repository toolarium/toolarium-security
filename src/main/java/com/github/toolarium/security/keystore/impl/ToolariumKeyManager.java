/*
 * ToolariumKeyManager.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.impl;

import com.github.toolarium.security.pki.util.PKIUtil;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Toolariun {@link KeyManager} which logs the verification.
 *
 * @author patrick
 */
public class ToolariumKeyManager extends X509ExtendedKeyManager {
    private static final Logger LOG = LoggerFactory.getLogger(ToolariumKeyManager.class);
    private final X509KeyManager x509KeyManager;
    
    
    /**
     * Constructor for ToolariumKeyManager
     *
     * @param x509KeyManager the key manager
     */
    public ToolariumKeyManager(X509KeyManager x509KeyManager) {
        this.x509KeyManager = x509KeyManager;
    }

    
    /**
     * @see javax.net.ssl.X509KeyManager#getPrivateKey(java.lang.String)
     */
    @Override
    public PrivateKey getPrivateKey(String alias) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Send {} private key.", alias);
        }
        
        PrivateKey key = x509KeyManager.getPrivateKey(alias);
        if (LOG.isDebugEnabled()) {
            PKIUtil.getInstance().processPrivateKeyInfo(LOG::debug, alias, key);
        }
        return key;
    }
    
    
    /**
     * @see javax.net.ssl.X509KeyManager#getCertificateChain(java.lang.String)
     */
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Send {} certificates.", alias);
        }
        
        X509Certificate[] certs =  x509KeyManager.getCertificateChain(alias);
        if (LOG.isDebugEnabled()) {
            PKIUtil.getInstance().processCertificate(LOG::debug, alias, certs);
        }
        return certs;
    }
    
    
    /**
     * @see javax.net.ssl.X509KeyManager#getClientAliases(java.lang.String, java.security.Principal[])
     */
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Get client aliases: {}", keyType);
        }
        
        return x509KeyManager.getClientAliases(keyType, issuers);
    }

    
    /**
     * @see javax.net.ssl.X509KeyManager#chooseServerAlias(java.lang.String, java.security.Principal[], java.net.Socket)
     */
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        String returnType = null;
        if (keyType != null) {
            returnType = x509KeyManager.chooseServerAlias(keyType, issuers, socket);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Choose {} as server alias: {}", keyType, returnType);
        }

        return returnType;
    }
    
    
    /**
     * @see javax.net.ssl.X509KeyManager#getServerAliases(java.lang.String, java.security.Principal[])
     */
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Get server aliases: {}", keyType);
        }
        
        String[] result = x509KeyManager.getServerAliases(keyType, issuers);
        return result;
    }    
    
    
    /**
     * @see javax.net.ssl.X509KeyManager#chooseClientAlias(java.lang.String[], java.security.Principal[], java.net.Socket)
     */
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        String returnType = null;
        if (keyType != null) {
            returnType = x509KeyManager.chooseClientAlias(keyType, issuers, socket);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Choose {} as client alias.", returnType);
        }

        return returnType;
    }


    /**
     * @see javax.net.ssl.X509ExtendedKeyManager#chooseEngineClientAlias(java.lang.String[], java.security.Principal[], javax.net.ssl.SSLEngine)
     */
    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        String returnType = null;
        if (keyType != null) {
            if (x509KeyManager instanceof X509ExtendedKeyManager) {
                returnType = ((X509ExtendedKeyManager) x509KeyManager).chooseEngineClientAlias(keyType, issuers, engine);
            } else {
                returnType = x509KeyManager.chooseClientAlias(keyType, issuers, null);
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Choose {} as engine client alias.", returnType);
        }

        return returnType;
    }


    /**
     * @see javax.net.ssl.X509ExtendedKeyManager#chooseEngineServerAlias(java.lang.String, java.security.Principal[], javax.net.ssl.SSLEngine)
     */
    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        String returnType = null;
        if (keyType != null) {
            if (x509KeyManager instanceof X509ExtendedKeyManager) {
                returnType = ((X509ExtendedKeyManager) x509KeyManager).chooseEngineServerAlias(keyType, issuers, engine);
            } else {
                returnType = x509KeyManager.chooseServerAlias(keyType, issuers, null);
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Choose {} as engine server alias: {}", keyType, returnType);
        }

        return returnType;
    }
}
