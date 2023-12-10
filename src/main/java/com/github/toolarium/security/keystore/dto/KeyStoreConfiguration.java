/*
 * KeyStoreConfiguration.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.dto;

import com.github.toolarium.common.security.ISecuredValue;
import com.github.toolarium.common.security.SecuredValue;
import java.io.File;
import java.security.KeyStore;
import java.util.Objects;


/**
 * Implements the {@link IKeyStoreConfiguration}.
 *  
 * @author patrick
 */
public class KeyStoreConfiguration implements IKeyStoreConfiguration {
    private File keyStorefile;
    private String provider;
    private String type;
    private String alias;
    private ISecuredValue<String> password;

    
    /**
     * Constructor for KeyStoreConfiguration
     */
    public KeyStoreConfiguration() {
        this(null, null, KeyStore.getDefaultType(), null, null);
    }

    
    /**
     * Constructor for KeyStoreConfiguration
     * 
     * @param keyStorefile the key store file
     * @param password the password
     */
    public KeyStoreConfiguration(File keyStorefile, ISecuredValue<String> password) {
        this(keyStorefile, null, KeyStore.getDefaultType(), null, password);
    }

    
    /**
     * Constructor for KeyStoreConfiguration
     * 
     * @param keyStorefile the key store file
     * @param provider the key store provider
     * @param type the key store type
     * @param alias the key store alias
     * @param password the password
     */
    public KeyStoreConfiguration(File keyStorefile, String provider, String type, String alias, ISecuredValue<String> password) {
        this.keyStorefile = keyStorefile;
        this.provider = provider;
        this.type = type;
        this.alias = alias;
        this.password = password;
    }


    /**
     * @see com.github.toolarium.security.keystore.dto.IKeyStoreConfiguration#getKeyStoreFile()
     */
    @Override
    public File getKeyStoreFile() {
        return keyStorefile;
    }
    
    
    /**
     * Set the key store file
     *
     * @param keyStorefile the key store file
     * @return the key store configuration
     */
    public KeyStoreConfiguration setKeyStorefile(File keyStorefile) {
        this.keyStorefile = keyStorefile;
        return this;
    }
    

    /**
     * @see com.github.toolarium.security.keystore.dto.IKeyStoreConfiguration#getKeyStoreProvider()
     */
    @Override
    public String getKeyStoreProvider() {
        return provider;
    }

    
    /**
     * Set the key store provider
     *
     * @param provider the key store provider
     * @return the key store configuration
     */
    public KeyStoreConfiguration setKeyStoreProvider(String provider) {
        this.provider = provider;
        return this;
    }

    
    /**
     * @see com.github.toolarium.security.keystore.dto.IKeyStoreConfiguration#getKeyStoreType()
     */
    @Override
    public String getKeyStoreType() {
        return type;
    }

    
    /**
     * Set the key store type
     *
     * @param type the key store type
     * @return the key store configuration
     */
    public KeyStoreConfiguration setKeyStoreType(String type) {
        this.type = type;
        return this;
    }

    
    /**
     * @see com.github.toolarium.security.keystore.dto.IKeyStoreConfiguration#getKeyStoreAlias()
     */
    @Override
    public String getKeyStoreAlias() {
        return alias;
    }

    
    /**
     * Set the key store alias
     *
     * @param alias the key store alias
     * @return the key store configuration
     */
    public KeyStoreConfiguration setKeyStoreAlias(String alias) {
        this.alias = alias;
        return this;
    }

    
    /**
     * @see com.github.toolarium.security.keystore.dto.IKeyStoreConfiguration#getKeyStorePassword()
     */
    @Override
    public ISecuredValue<String> getKeyStorePassword() {
        return password;
    }
    
    
    /**
     * Set the key store password
     *
     * @param password the key store password
     * @return the key store configuration
     */
    public KeyStoreConfiguration setKeyStorePassword(String password) {
        return setKeyStorePassword(new SecuredValue<String>(password, "..."));
    }


    /**
     * Set the key store password
     *
     * @param password the key store password
     * @return the key store configuration
     */
    public KeyStoreConfiguration setKeyStorePassword(ISecuredValue<String> password) {
        this.password = password;
        return this;
    }


    /**
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return Objects.hash(alias, keyStorefile, password, provider, type);
    }


    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        
        if (obj == null) {
            return false;
        }
        
        if (getClass() != obj.getClass()) {
            return false;
        }
        
        KeyStoreConfiguration other = (KeyStoreConfiguration) obj;
        return Objects.equals(alias, other.alias) && Objects.equals(keyStorefile, other.keyStorefile)
                && Objects.equals(password, other.password) && Objects.equals(provider, other.provider)
                && Objects.equals(type, other.type);
    }


    /**
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "KeyStoreConfiguration [keyStorefile=" + keyStorefile + ", provider=" + provider + ", type=" + type + ", alias=" + alias + ", password=" + password + "]";
    }
}
