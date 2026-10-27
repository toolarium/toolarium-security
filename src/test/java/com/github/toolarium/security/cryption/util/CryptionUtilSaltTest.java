/*
 * CryptionUtilSaltTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.cryption.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;


/**
 * Test the salt handling of the {@link CryptionUtil} (N19).
 *
 * @author patrick
 */
public class CryptionUtilSaltTest {

    /**
     * Constructor for CryptionUtilSaltTest
     */
    public CryptionUtilSaltTest() {
        // NOP
    }


    /**
     * Test the salt generation
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testGenerateSalt() throws GeneralSecurityException {
        byte[] salt1 = CryptionUtil.getInstance().generateSalt();
        byte[] salt2 = CryptionUtil.getInstance().generateSalt();
        assertEquals(16, salt1.length);
        assertFalse(Arrays.equals(salt1, salt2));

        SecretKeySpec key1 = CryptionUtil.getInstance().createSecretKeySpec("passphrase".toCharArray(), salt1, 10_000);
        SecretKeySpec key2 = CryptionUtil.getInstance().createSecretKeySpec("passphrase".toCharArray(), salt2, 10_000);
        assertNotNull(key1);
        assertFalse(Arrays.equals(key1.getEncoded(), key2.getEncoded()));
    }


    /**
     * Invalid salt, iteration count or passphrase is rejected
     */
    @Test
    public void testInvalidParameters() {
        assertThrows(GeneralSecurityException.class, () -> CryptionUtil.getInstance().createSecretKeySpec("passphrase".toCharArray(), null, 10_000));
        assertThrows(GeneralSecurityException.class, () -> CryptionUtil.getInstance().createSecretKeySpec("passphrase".toCharArray(), new byte[8], 10_000));
        assertThrows(GeneralSecurityException.class, () -> CryptionUtil.getInstance().createSecretKeySpec("passphrase".toCharArray(), new byte[16], 0));
        assertThrows(GeneralSecurityException.class, () -> CryptionUtil.getInstance().createSecretKeySpec((char[]) null, new byte[16], 10_000));
    }
}
