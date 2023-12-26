/*
 * Modulo11Test.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.checkdigit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;


/**
 * Test modulo 11
 * 
 * @author patrick
 */
public class Modulo11Test {

    /**
     * Test modulo 11
     */
    @Test
    public void testModulo11() {
        assertEquals("3", Modulo11.getInstance().createCheckDigit("S2345435454384323"));
        assertTrue(Modulo11.getInstance().validate("S23454354543843233"));

        assertEquals("4", Modulo11.getInstance().createCheckDigit("020188954"));
        assertTrue(Modulo11.getInstance().validate("0201889544"));

        assertEquals("4", Modulo11.getInstance().createCheckDigit("0-201-88954"));
        assertTrue(Modulo11.getInstance().validate("0-201-88954-4"));
        assertTrue(Modulo11.getInstance().validate("0 201 88954 4"));

        assertTrue(Modulo11.getInstance().validate("0-201-32563-2"));

        assertEquals("X", Modulo11.getInstance().createCheckDigit("0-201-88951"));
        assertTrue(Modulo11.getInstance().validate("0-201-88951-X"));
        assertTrue(Modulo11.getInstance().validate("0 201 88951 X"));

        assertFalse(Modulo11.getInstance().validate("0-201-88951-0"));
        assertFalse(Modulo11.getInstance().validate("0-201-88951-1"));
        assertFalse(Modulo11.getInstance().validate("0-201-88951-2"));
        assertFalse(Modulo11.getInstance().validate("0-201-88951-3"));
        assertFalse(Modulo11.getInstance().validate("0-201-88951-4"));
        assertFalse(Modulo11.getInstance().validate("0-201-88951-5"));
        assertFalse(Modulo11.getInstance().validate("0-201-88951-6"));
        assertFalse(Modulo11.getInstance().validate("0-201-88951-7"));
        assertFalse(Modulo11.getInstance().validate("0-201-88951-8"));
        assertFalse(Modulo11.getInstance().validate("0-201-88951-9"));
    }
}
