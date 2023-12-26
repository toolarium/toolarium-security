/*
 * HashIdTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.hash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.common.util.RandomGenerator;
import com.github.toolarium.security.checkdigit.Modulo10;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the {@link HashId}.
 *  
 * @author patrick
 */
public class HashIdTest {
    private static final Logger LOG = LoggerFactory.getLogger(HashIdTest.class);
    private String salt = "this is my salt";


    /**
     * Test default salt
     */
    @Test
    public void testHasDefaultSalt() {
        assertEquals(HashId.createHashId().encrypt(1, 2, 3), "katKSA");
    }    

    
    /**
     * Test correct salt
     */
    @Test
    public void testHasTheCorrectSalt() {
        assertEquals(HashId.createHashId(salt).getSalt(), "this is my salt");
    }

    
    /**
     * Test min lentgh zero
     */
    @Test
    public void testDefaultsToTheMinimumLength0() {
        assertEquals(HashId.createHashId(salt).getMinHashLength(), 0);
    }
    
    
    /**
     * Test encrypt single number
     */
    @Test
    public void testEncryptsASingleNumber() {
        assertEquals(HashId.createHashId(salt).encrypt(12345), "ryBo");
        assertEquals(HashId.createHashId(salt).encrypt(1), "LX");
        assertEquals(HashId.createHashId(salt).encrypt(22), "5B");
        assertEquals(HashId.createHashId(salt).encrypt(333), "o49");
        assertEquals(HashId.createHashId(salt).encrypt(9999), "GKnB");
        assertEquals(HashId.createHashId(salt).encrypt(999444), "Bq5ayK");
        assertEquals(HashId.createHashId(salt).encrypt(-999444), "Bq5ayK");
        assertEquals(HashId.createHashId(salt).encrypt("f0cc26fe-690b-452e-b6ec-9c737b9575b2".hashCode()), "gzjR4M5");
        assertEquals(HashId.createHashId(salt).decrypt("gzjR4M5")[0], (-1) * "f0cc26fe-690b-452e-b6ec-9c737b9575b2".hashCode());
    }

    
    /**
     * Test encrypt string if no numbers
     */
    @Test
    public void testEncryptsAListOfNumbers() {
        assertEquals(HashId.createHashId(salt).encrypt(683, 94108, 123, 5), "zBphL54nuMyu5");
        assertEquals(HashId.createHashId(salt).encrypt(1, 2, 3), "eGtrS8");
        assertEquals(HashId.createHashId(salt).encrypt(2, 4, 6), "9Kh7fz");
        assertEquals(HashId.createHashId(salt).encrypt(99, 25), "dAECX");
    }

    
    /**
     * Test empty string if no numbers
     */
    @Test
    public void testReturnsAnEmptyStringIfNoNumbers() {
        assertEquals(HashId.createHashId(salt).encrypt(), "");
    }

    
    /**
     * Test encrypt to a min length
     */
    @Test
    public void testCanEncryptToAMinimumLength() {
        assertEquals(HashId.createHashId(salt, 8).encrypt(1), "b9iLXiAa");
    }

    
    /**
     * Test repeating patterns
     */
    @Test
    public void testDoesNotProduceRepeatingPatternsForIdenticalNumbers() {
        assertEquals(HashId.createHashId(salt).encrypt(5, 5, 5, 5), "GLh5SMs9");
    }

    
    /**
     * Test incremental number pattern
     */
    @Test
    public void testDoesNotProduceRepeatingPatternsForIncrementedNumbers() {
        assertEquals(HashId.createHashId(salt).encrypt(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), "zEUzfySGIpuyhpF6HaC7");
    }

    
    /**
     * Test similar between incrementing number hashes
     */
    @Test
    public void testDoesNotProduceSimilaritiesBetweenIncrementingNumberHashes() {
        assertEquals(HashId.createHashId(salt).encrypt(1), "LX");
        assertEquals(HashId.createHashId(salt).encrypt(2), "ed");
        assertEquals(HashId.createHashId(salt).encrypt(3), "o9");
        assertEquals(HashId.createHashId(salt).encrypt(4), "4n");
        assertEquals(HashId.createHashId(salt).encrypt(5), "a5");
    }

    
    /**
     * Test decrypt
     */
    @Test
    public void testDecryptsAnEncryptedNumber() {
        assertArrayEquals(HashId.createHashId(salt).decrypt("ryBo"), new long[] {12345 });
        assertArrayEquals(HashId.createHashId(salt).decrypt("qkpA"), new long[] {1337 });
        assertArrayEquals(HashId.createHashId(salt).decrypt("6aX"), new long[] {808 });
        assertArrayEquals(HashId.createHashId(salt).decrypt("gz9"), new long[] {303 });
        assertArrayEquals(HashId.createHashId(salt).decrypt("Bq5ayK"), new long[] {999444 });
    }

    
    /**
     * Test decrypt 
     */
    @Test
    public void testDecryptsAListOfEncryptedNumbers() {
        assertArrayEquals(HashId.createHashId(salt).decrypt("zBphL54nuMyu5"), new long[] {683, 94108, 123, 5 });
        assertArrayEquals(HashId.createHashId(salt).decrypt("kEFy"), new long[] {1, 2 });
        assertArrayEquals(HashId.createHashId(salt).decrypt("Aztn"), new long[] {6, 5 });
    }

    
    /**
     * Test decrypt 
     */
    @Test
    public void testDoesNotDecryptWithADifferentSalt() {
        assertArrayEquals(HashId.createHashId(salt).decrypt("ryBo"), new long[] {12345 });
        assertArrayEquals(HashId.createHashId("this is my pepper").decrypt("ryBo"), new long[0]);
    }

    
    /**
     * Test decrypt 
     */
    @Test
    public void testCanDecryptFromAHashWithAMinimumLength() {
        assertArrayEquals(HashId.createHashId(salt, 8).decrypt("b9iLXiAa"), new long[] {1 });
    }

    
    /**
     * Test decrypt 
     */
    @Test
    public void testRaisesAnArgumentNullExceptionWhenAlphabetIsNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            HashId.createHashId("", 0, null); }, "Expected");
    }

    
    /**
     * Test decrypt 
     */
    @Test
    public void testRaisesAnArgumentNullExceptionIfAlphabetContainsLessThan4UniqueCharacters() {
        assertThrows(IllegalArgumentException.class, () -> {
            HashId.createHashId("", 0, "aadsss"); }, "Expected");
    }
    
    
    /**
     * Test download hash
     */
    @Test
    public void testDownloadHashSample() {
        long hash = 23443265784367832L;

        // create hash id instance
        HashId hashId1 = HashId.createHashId(UUID.randomUUID().toString() /* salt */, 0); // unique salt 
        HashId hashId2 = HashId.createHashId("MyOtherPrOduCt" /* salt */, 0);

        // create download identifier
        String downloadId = hashId1.encrypt(hash, 
                                            Modulo10.getInstance().createCheckDigit("" + hash),
                                            Calendar.getInstance().getTime().getTime(),
                                            RandomGenerator.getInstance().getLongRandom(), RandomGenerator.getInstance().getLongRandom(), RandomGenerator.getInstance().getLongRandom()); // blow up hash length

        LOG.debug("Download URL: " + downloadId);
        assertTrue(downloadId.length() > 64);

        // decode
        long[] result1 = hashId1.decrypt(downloadId);
        long[] result2 = hashId2.decrypt(downloadId);
        assertEquals(0, result2.length);
        
        LOG.debug("Hash        : " + result1[0]);
        LOG.debug("Timestamp   : " + new Date(result1[2]));

        // validate
        assertEquals(hash, result1[0]);
        assertTrue(new Date().after(new Date(result1[2])));
        assertTrue(Modulo10.getInstance().validate("" + result1[0] + result1[1]));
    }


    /**
     * Test can encrypt with a swapped custom
     */
    @Test
    public void testCanEncryptWithASwappedCustom() {
        assertEquals(HashId.createHashId("this is my salt", 0, "abcd").encrypt(1, 2, 3, 4, 5), "adcdacddcdaacdad");
    }
    
    
    /**
     * Test
     */
    @Test
    public void testHash() {
        assertEquals(HashId.createHashId().encrypt("jptools.dao.impl.ABRawDAOImpl".hashCode()), "kapLMdE7");
    }
    
    
    /**
     * Assert  
     * @param decrypt the decrypted
     * @param ls the longs
     */
    private void assertArrayEquals(long[] decrypt, long[] ls) {
        if (decrypt.length != ls.length) {
            for (int i = 0; i < decrypt.length; i++) {
                LOG.debug("D:" + decrypt[i]);
            }
            for (int i = 0; i < ls.length; i++) {
                LOG.debug("l:" + ls[i]);
            }

        }
        assertEquals(decrypt.length, ls.length);

        for (int i = 0; i < decrypt.length; i++) {
            assertEquals(decrypt[i], ls[i]);
        }
    }
}
