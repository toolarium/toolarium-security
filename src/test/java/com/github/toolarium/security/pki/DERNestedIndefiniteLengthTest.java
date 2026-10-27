/*
 * DERNestedIndefiniteLengthTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.toolarium.security.pki.impl.rsa.der.DERInputStream;
import com.github.toolarium.security.pki.impl.rsa.der.DERValue;
import java.io.IOException;
import org.junit.jupiter.api.Test;


/**
 * Test the DER parser with nested elements in indefinite length encoding: they must be rejected, never be read wrong.
 *
 * @author patrick
 */
public class DERNestedIndefiniteLengthTest {

    /**
     * Constructor for DERNestedIndefiniteLengthTest
     */
    public DERNestedIndefiniteLengthTest() {
        // NOP
    }


    /**
     * SEQUENCE { INTEGER 5, SEQUENCE (indefinite length) { INTEGER 7 }, INTEGER 9 }: the nested element in indefinite
     * length encoding is rejected (before it was read from the wrong position and INTEGER 9 got lost).
     */
    @Test
    public void testNestedIndefiniteLengthSequence() {
        byte[] data = {
            0x30, 0x0D,                                      // SEQUENCE, 13 bytes
            0x02, 0x01, 0x05,                                //   INTEGER 5
            0x30, (byte) 0x80, 0x02, 0x01, 0x07, 0x00, 0x00, //   SEQUENCE (indefinite) { INTEGER 7 } end-of-contents
            0x02, 0x01, 0x09                                 //   INTEGER 9
        };

        assertThrows(IOException.class, () -> new DERInputStream(data).getSequence(3));
    }


    /**
     * SEQUENCE { SEQUENCE (indefinite length) { INTEGER 7 }, INTEGER 9 }: the nested element is the first one, it must
     * be read correctly or be rejected, but the following INTEGER 9 must not get lost.
     */
    @Test
    public void testFirstNestedIndefiniteLengthSequence() {
        byte[] data = {
            0x30, 0x0A,                                      // SEQUENCE, 10 bytes
            0x30, (byte) 0x80, 0x02, 0x01, 0x07, 0x00, 0x00, //   SEQUENCE (indefinite) { INTEGER 7 } end-of-contents
            0x02, 0x01, 0x09                                 //   INTEGER 9
        };

        DERValue[] values;
        try {
            values = new DERInputStream(data).getSequence(2);
        } catch (IOException e) {
            // rejected: fine
            return;
        }

        assertEquals(2, values.length);
    }
}
