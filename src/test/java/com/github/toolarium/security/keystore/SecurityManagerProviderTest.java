/*
 * SecurityManagerProviderTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.github.toolarium.security.certificate.util.PKIUtilTest;
import com.github.toolarium.security.keystore.dto.IKeyStoreConfiguration;
import com.github.toolarium.security.keystore.dto.KeyStoreConfiguration;
import com.github.toolarium.security.keystore.util.KeyStoreUtilTest;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;


/**
 * Test the {@link SecurityManagerProviderFactory}. 
 * @author patrick
 */
public class SecurityManagerProviderTest {

    
    /**
     * Test the key store configuration
     *
     * @throws IOException in case of a file read error
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void test() throws GeneralSecurityException, IOException {
        IKeyStoreConfiguration keyManagerKeyStoreConfiguration = new KeyStoreConfiguration(Paths.get(PKIUtilTest.TEST_RESOURCE_PATH, KeyStoreUtilTest.PKCS12_TESTFILE).toFile(), 
                                                                                           null, 
                                                                                           "PKCS12", 
                                                                                           KeyStoreUtilTest.PKCS12_ALIAS, 
                                                                                           KeyStoreUtilTest.PKCS12_KEYSTORE_PASSWORD);
        ISecurityManagerProvider securityManagerProvider = SecurityManagerProviderFactory.getInstance().getSecurityManagerProvider(null, keyManagerKeyStoreConfiguration);
        assertNotNull(securityManagerProvider);
        assertNotNull(securityManagerProvider.getKeyManagers());
        assertNotNull(securityManagerProvider.getTrustManagers());
    }
}
