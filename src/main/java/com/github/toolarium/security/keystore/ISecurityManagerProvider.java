/*
 * IKeystore.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore;

import java.security.GeneralSecurityException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;


/**
 * Defines the security manager provider
 * 
 * @author patrick
 */
public interface ISecurityManagerProvider {

    /**
     * Returns the key manager.
     *
     * @return the key managers
     * @throws GeneralSecurityException if it can not be initialised.
     */
    KeyManager[] getKeyManagers() throws GeneralSecurityException;

    
    /**
     * Returns the trust manager.
     *
     * @return the trust managers
     * @throws GeneralSecurityException if it can not be initialised.
     */
    TrustManager[] getTrustManagers() throws GeneralSecurityException;
}
