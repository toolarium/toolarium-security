/*
 * Modulo11FindingsTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.checkdigit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;


/**
 * Test the fix of the finding N55 of the {@link Modulo11}: no negative weights and no negative modulo.
 *
 * @author patrick
 */
public class Modulo11FindingsTest {

    /**
     * Constructor for Modulo11FindingsTest
     */
    public Modulo11FindingsTest() {
        // NOP
    }


    /**
     * More than 10 digits give a single check digit; before the fix the negative sum gave e.g. "14".
     */
    @Test
    public void testLongInput() {
        assertEquals("3", Modulo11.getInstance().createCheckDigit("0000000000999999"));
        assertTrue(Modulo11.getInstance().validate("00000000009999993"));

        for (int i = 0; i < 100; i++) {
            String data = "1234567890" + Long.toString(i * 7919L) + "999999999";
            String checkDigit = Modulo11.getInstance().createCheckDigit(data);
            assertEquals(1, checkDigit.length());
            assertTrue(Modulo11.getInstance().validate(data + checkDigit));
        }
    }


    /**
     * Inputs with up to 10 digits give the same result as before.
     */
    @Test
    public void testShortInput() {
        assertEquals("4", Modulo11.getInstance().createCheckDigit("020188954"));
        assertEquals("X", Modulo11.getInstance().createCheckDigit("020188951"));
        assertEquals("2", Modulo11.getInstance().createCheckDigit("020132563"));
    }
}
