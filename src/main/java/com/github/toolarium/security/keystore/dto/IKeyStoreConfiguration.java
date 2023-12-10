/*
 * ISecurityConfiguration.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.dto;

import com.github.toolarium.common.security.ISecuredValue;
import java.io.File;


/**
 * Defines the security manager provider configuration
 * 
 * @author patrick
 */
public interface IKeyStoreConfiguration {

    /**
     * Get the key store file 
     *
     * @return the key store file
     */
    File getKeyStoreFile();

    
    /**
     * Get the key store provider 
     *
     * @return the key store provider or null
     */
    String getKeyStoreProvider();

    
    /**
     * Get the key store type 
     *
     * @return the key store type or null
     */
    String getKeyStoreType();

    
    /**
     * Get the key store alias 
     *
     * @return the key store alias or null
     */
    String getKeyStoreAlias();
    
    
    /**
     * Get the key store password
     *
     * @return the key store password or null
     */
    ISecuredValue<String> getKeyStorePassword();
}
