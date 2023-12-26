/*
 * Modulo10Test.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.checkdigit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;


/**
 * Test modulo 10
 * 
 * @author patrick
 */
public class Modulo10Test {
    
    /**
     * Test modulo 10
     */
    @Test
    public void testModulo10() {
        assertEquals(5, Modulo10.getInstance().createCheckDigit("123 456 789 01").longValue());
        assertTrue(Modulo10.getInstance().validate("123 456 789 015"));

        assertEquals(9, Modulo10.getInstance().createCheckDigit("4563 9601 2200 199").longValue());
        assertTrue(Modulo10.getInstance().validate("4563 9601 2200 1999"));

        assertEquals(1, Modulo10.getInstance().createCheckDigit("446-667-65").longValue());
        assertTrue(Modulo10.getInstance().validate("446-667-651"));

        assertFalse(Modulo10.getInstance().validate("446-667-650"));
        assertFalse(Modulo10.getInstance().validate("446-667-652"));
        assertFalse(Modulo10.getInstance().validate("446-667-653"));
        assertFalse(Modulo10.getInstance().validate("446-667-654"));
        assertFalse(Modulo10.getInstance().validate("446-667-655"));
        assertFalse(Modulo10.getInstance().validate("446-667-656"));
        assertFalse(Modulo10.getInstance().validate("446-667-657"));
        assertFalse(Modulo10.getInstance().validate("446-667-658"));
        assertFalse(Modulo10.getInstance().validate("446-667-659"));
        assertEquals(5, Modulo10.getInstance().createCheckDigit("12345").longValue());
        assertEquals(6, Modulo10.getInstance().createCheckDigit("123456").longValue());
        assertEquals(4, Modulo10.getInstance().createCheckDigit("1234567").longValue());
        assertEquals(0, Modulo10.getInstance().createCheckDigit("114123456789").longValue());
        assertEquals(3, Modulo10.getInstance().createCheckDigit("7992739871").longValue());
        assertEquals(1, Modulo10.getInstance().createCheckDigit("55789602581076").longValue());
    }
}
