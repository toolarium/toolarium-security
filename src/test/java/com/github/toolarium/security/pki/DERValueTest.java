/*
 * DERValueTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.pki.impl.rsa.der.DERValue;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.junit.jupiter.api.Test;


/**
 * Test the {@link DERValue}: values can be read more than once, empty values and invalid bit strings.
 *
 * @author patrick
 */
public class DERValueTest {

    /**
     * Constructor for DERValueTest
     */
    public DERValueTest() {
        // NOP
    }


    /**
     * The getters do not consume the value: it can be read more than once and equals gives the same result after a
     * getter call.
     *
     * @throws IOException in case of error
     */
    @Test
    public void testReadValueMoreThanOnce() throws IOException {
        byte[] octetStringEncoding = {0x04, 0x03, 1, 2, 3};
        DERValue octetString = createValue(octetStringEncoding);
        assertArrayEquals(new byte[] {1, 2, 3}, octetString.getOctetString());
        assertArrayEquals(new byte[] {1, 2, 3}, octetString.getOctetString());
        assertTrue(octetString.equals(createValue(octetStringEncoding)));
        assertArrayEquals(octetStringEncoding, octetString.toByteArray());
        assertArrayEquals(octetStringEncoding, octetString.toByteArray());

        DERValue integer = createValue(new byte[] {0x02, 0x02, 0x01, 0x00});
        assertEquals(256, integer.getInteger().toInt());
        assertEquals(256, integer.getInteger().toInt());
        assertEquals(integer.hashCode(), createValue(new byte[] {0x02, 0x02, 0x01, 0x00}).hashCode());

        DERValue sequence = createValue(new byte[] {0x30, 0x03, 0x02, 0x01, 0x05});
        assertEquals(5, sequence.toDERInputStream().getInteger().toInt());
        assertEquals(5, sequence.toDERInputStream().getInteger().toInt());
    }


    /**
     * An empty value can be read: it has no content.
     *
     * @throws IOException in case of error
     */
    @Test
    public void testEmptyValue() throws IOException {
        DERValue octetString = createValue(new byte[] {0x04, 0x00});
        assertEquals(0, octetString.length());
        assertArrayEquals(new byte[0], octetString.getOctetString());
        assertArrayEquals(new byte[] {0x04, 0x00}, octetString.toByteArray());
        assertTrue(octetString.equals(createValue(new byte[] {0x04, 0x00})));
        assertEquals("", createValue(new byte[] {DERValue.tag_UTF8String, 0x00}).getUTF8String());
    }


    /**
     * Bit strings with an invalid number of unused bits are rejected with an {@link IOException}.
     *
     * @throws IOException in case of error
     */
    @Test
    public void testInvalidBitString() throws IOException {
        // valid: no unused bits, one unused bit
        assertArrayEquals(new byte[] {(byte) 0xFF}, createValue(new byte[] {0x03, 0x02, 0x00, (byte) 0xFF}).getBitString());
        assertEquals(7, createValue(new byte[] {0x03, 0x02, 0x01, (byte) 0xFE}).getUnalignedBitString().length());

        // empty bit string, more than 7 unused bits, unused bits without content
        byte[][] invalidBitStrings = {{0x03, 0x00}, {0x03, 0x02, 0x08, (byte) 0xFF}, {0x03, 0x02, (byte) 0xFF, (byte) 0xFF}, {0x03, 0x01, 0x01}};
        for (byte[] invalidBitString : invalidBitStrings) {
            DERValue value = createValue(invalidBitString);
            assertThrows(IOException.class, () -> value.getBitString());
            assertThrows(IOException.class, () -> value.getUnalignedBitString());
        }
    }


    /**
     * Create a value from its encoding.
     *
     * @param encoding the encoding
     * @return the value
     * @throws IOException in case of error
     */
    private DERValue createValue(byte[] encoding) throws IOException {
        return new DERValue(new ByteArrayInputStream(encoding));
    }
}
