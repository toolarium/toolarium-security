/*
 * CryptUtilSaltTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;


/**
 * Test the salt handling of the {@link CryptUtil} (N19).
 *
 * @author patrick
 */
public class CryptUtilSaltTest {

    /**
     * Constructor for CryptUtilSaltTest
     */
    public CryptUtilSaltTest() {
        // NOP
    }


    /**
     * Test the salt generation
     *
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testGenerateSalt() throws GeneralSecurityException {
        byte[] salt1 = CryptUtil.getInstance().generateSalt();
        byte[] salt2 = CryptUtil.getInstance().generateSalt();
        assertEquals(16, salt1.length);
        assertFalse(Arrays.equals(salt1, salt2));

        SecretKeySpec key1 = CryptUtil.getInstance().createSecretKeySpec("passphrase".toCharArray(), salt1, 10_000);
        SecretKeySpec key2 = CryptUtil.getInstance().createSecretKeySpec("passphrase".toCharArray(), salt2, 10_000);
        assertNotNull(key1);
        assertFalse(Arrays.equals(key1.getEncoded(), key2.getEncoded()));
    }


    /**
     * Invalid salt, iteration count or passphrase is rejected
     */
    @Test
    public void testInvalidParameters() {
        assertThrows(GeneralSecurityException.class, () -> CryptUtil.getInstance().createSecretKeySpec("passphrase".toCharArray(), null, 10_000));
        assertThrows(GeneralSecurityException.class, () -> CryptUtil.getInstance().createSecretKeySpec("passphrase".toCharArray(), new byte[8], 10_000));
        assertThrows(GeneralSecurityException.class, () -> CryptUtil.getInstance().createSecretKeySpec("passphrase".toCharArray(), new byte[16], 0));
        assertThrows(GeneralSecurityException.class, () -> CryptUtil.getInstance().createSecretKeySpec((char[]) null, new byte[16], 10_000));
    }
}
