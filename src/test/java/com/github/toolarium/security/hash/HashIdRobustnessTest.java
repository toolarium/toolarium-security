/*
 * HashIdRobustnessTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.hash;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;


/**
 * Test the {@link HashId} with edge cases (N28).
 *
 * @author patrick
 */
public class HashIdRobustnessTest {

    /**
     * Constructor for HashIdRobustnessTest
     */
    public HashIdRobustnessTest() {
        // NOP
    }


    /**
     * Long.MIN_VALUE has no absolute value and must be rejected
     */
    @Test
    public void testMinValue() {
        assertThrows(IllegalArgumentException.class, () -> HashId.createHashId().encrypt(Long.MIN_VALUE));
        assertThrows(IllegalArgumentException.class, () -> HashId.createHashId().encrypt((long[]) null));
    }


    /**
     * Large numbers must be encoded and decoded without overflow or precision loss
     */
    @Test
    public void testLargeNumbers() {
        HashId hashId = HashId.createHashId("this is my salt");
        long[] numbers = new long[] {Long.MAX_VALUE, Long.MAX_VALUE - 1, 1L << 60};
        assertArrayEquals(numbers, hashId.decrypt(hashId.encrypt(numbers)));
        assertArrayEquals(new long[] {Long.MAX_VALUE}, hashId.decrypt(hashId.encrypt(Long.MAX_VALUE)));
    }


    /**
     * The minimum hash length must also be respected if the guard index sum overflows
     */
    @Test
    public void testMinHashLengthWithOverflow() {
        HashId hashId = HashId.createHashId("this is my salt", 20);
        long[] numbers = new long[] {2147483648L, 5L};
        String hash = hashId.encrypt(numbers);
        assertTrue(hash.length() >= 20, "Hash too short: " + hash);
        assertArrayEquals(numbers, hashId.decrypt(hash));
    }


    /**
     * Invalid hashes are decoded to an empty array instead of throwing an exception
     */
    @Test
    public void testInvalidHash() {
        HashId hashId = HashId.createHashId("this is my salt");
        assertEquals(0, hashId.decrypt("!!!!").length);
        assertEquals(0, hashId.decrypt("").length);
        assertEquals(0, hashId.decrypt(null).length);
    }
}
