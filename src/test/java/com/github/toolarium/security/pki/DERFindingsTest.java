/*
 * DERFindingsTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.pki.impl.rsa.comporator.ByteArrayTagOrder;
import com.github.toolarium.security.pki.impl.rsa.data.BigInt;
import com.github.toolarium.security.pki.impl.rsa.data.BitArray;
import com.github.toolarium.security.pki.impl.rsa.der.DERIndefLenConverter;
import com.github.toolarium.security.pki.impl.rsa.der.DERInputStream;
import com.github.toolarium.security.pki.impl.rsa.der.DEROutputStream;
import com.github.toolarium.security.pki.impl.rsa.der.DERValue;
import com.github.toolarium.security.pki.impl.rsa.der.ObjectIdentifier;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.Test;


/**
 * Tests the fixes of the DER parser findings N43, N45, N83, N84, N89, N90, N91, N92, N93, N97 and N98.
 *
 * @author patrick
 */
public class DERFindingsTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final int MAX_DER_LENGTH = 32 * 1024 * 1024;
    private static final String OID_PREFIX = "1.2";


    /**
     * Constructor for DERFindingsTest
     */
    public DERFindingsTest() {
        // NOP
    }


    /**
     * A sequence with many elements is parsed in linear time (N43).
     */
    @Test
    public void testLargeSequence() {
        final int count = 200000;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        writeLength(out, count * 2);
        for (int i = 0; i < count; i++) {
            out.write(DERValue.tag_Null);
            out.write(0x00);
        }
        byte[] data = out.toByteArray();

        DERValue[] values = assertTimeoutPreemptively(TIMEOUT, () -> new DERInputStream(data).getSequence(1));
        assertEquals(count, values.length);
    }


    /**
     * Many indefinite-length sections are converted in linear time and the definite lengths are correct (N43).
     *
     * @throws IOException in case of error
     */
    @Test
    public void testManyIndefiniteLengthSections() throws IOException {
        final int count = 50000;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        out.write(0x80);
        for (int i = 0; i < count; i++) {
            out.write(new byte[] {0x30, (byte) 0x80, 0x00, 0x00}, 0, 4);
        }
        out.write(0x00);
        out.write(0x00);
        byte[] data = out.toByteArray();

        byte[] converted = assertTimeoutPreemptively(TIMEOUT, () -> new DERIndefLenConverter().convert(data));
        assertEquals(count, new DERInputStream(converted).getSequence(1).length);
    }


    /**
     * Nested indefinite-length sections with a long form length are converted correctly (N43).
     *
     * @throws IOException in case of error
     */
    @Test
    public void testNestedIndefiniteLengthSections() throws IOException {
        // SEQUENCE (indefinite) { SEQUENCE (indefinite) { OCTET STRING (127 bytes) } INTEGER 9 }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[] {0x30, (byte) 0x80, 0x30, (byte) 0x80, DERValue.tag_OctetString, 0x7F}, 0, 6);
        out.write(new byte[127], 0, 127);
        out.write(new byte[] {0x00, 0x00, DERValue.tag_Integer, 0x01, 0x09, 0x00, 0x00}, 0, 7);

        byte[] converted = new DERIndefLenConverter().convert(out.toByteArray());
        DERValue[] values = new DERInputStream(converted).getSequence(2);
        assertEquals(2, values.length);
        assertEquals(127, values[0].toDERInputStream().getOctetString().length);
        assertEquals(9, values[1].getInteger().toInt());
    }


    /**
     * Too deeply nested indefinite-length sections are rejected with an {@link IOException} (N43, N93).
     */
    @Test
    public void testDeepIndefiniteLengthNesting() {
        assertDoesNotThrow(() -> new DERIndefLenConverter().convert(createNestedIndefiniteLength(100)));

        byte[] data = createNestedIndefiniteLength(150);
        assertThrows(IOException.class, () -> new DERIndefLenConverter().convert(data));
        assertThrows(IOException.class, () -> new DERValue(new ByteArrayInputStream(data)));

        // the constructor declares no IOException: an IllegalArgumentException with the IOException as cause
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> new DERInputStream(data));
        assertTrue(e.getCause() instanceof IOException);
    }


    /**
     * An indefinite-length value read from an input stream is limited to the maximum DER length (N43).
     */
    @Test
    public void testIndefiniteLengthStreamLimit() {
        GeneratingInputStream in = new GeneratingInputStream(new byte[] {0x30, (byte) 0x80});
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            assertThrows(IOException.class, () -> new DERValue(in));
        });
        assertTrue(in.getCount() <= MAX_DER_LENGTH + 65536L, "read too much: " + in.getCount());
    }


    /**
     * The empty bit string can be read (N45).
     *
     * @throws IOException in case of error
     */
    @Test
    public void testEmptyBitString() throws IOException {
        byte[] data = {DERValue.tag_BitString, 0x01, 0x00};
        DERValue value = new DERValue(new ByteArrayInputStream(data));
        assertArrayEquals(new byte[0], value.getBitString());

        BitArray bitArray = value.getUnalignedBitString();
        assertEquals(0, bitArray.length());
        assertArrayEquals(new byte[0], bitArray.toByteArray());
        assertEquals("", bitArray.toString());

        assertEquals(0, new DERInputStream(data).getUnalignedBitString().length());
        assertArrayEquals(new byte[0], new DERInputStream(data).getBitString());
        assertEquals(0, new BitArray(0, new byte[0]).length());
    }


    /**
     * Invalid unused bits of an unaligned bit string are rejected (N83).
     *
     * @throws IOException in case of error
     */
    @Test
    public void testUnalignedBitStringUnusedBits() throws IOException {
        assertEquals(7, new DERInputStream(new byte[] {DERValue.tag_BitString, 0x02, 0x01, (byte) 0xFE}).getUnalignedBitString().length());

        byte[][] invalidBitStrings = {{DERValue.tag_BitString, 0x02, 0x08, (byte) 0xFF},
                                      {DERValue.tag_BitString, 0x02, (byte) 0xFF, (byte) 0xFF},
                                      {DERValue.tag_BitString, 0x01, 0x05},
                                      {DERValue.tag_BitString, 0x01}};
        for (byte[] invalidBitString : invalidBitStrings) {
            assertThrows(IOException.class, () -> new DERInputStream(invalidBitString).getUnalignedBitString());
        }
    }


    /**
     * A length larger than the available data is rejected (N84).
     */
    @Test
    public void testLengthLargerThanAvailable() {
        byte[] octetString = {DERValue.tag_OctetString, (byte) 0x83, 0x10, 0x00, 0x00, 0x01};
        assertThrows(IOException.class, () -> new DERInputStream(octetString).getOctetString());

        byte[] bitString = {DERValue.tag_BitString, (byte) 0x83, 0x10, 0x00, 0x00, 0x00, 0x01};
        assertThrows(IOException.class, () -> new DERInputStream(bitString).getBitString());
        assertThrows(IOException.class, () -> new DERInputStream(bitString).getUnalignedBitString());

        byte[] utf8String = {DERValue.tag_UTF8String, (byte) 0x83, 0x10, 0x00, 0x00, 0x41};
        assertThrows(IOException.class, () -> new DERInputStream(utf8String).getUTF8String());
    }


    /**
     * The INTEGER zero is encoded as 02 01 00 (N89).
     *
     * @throws IOException in case of error
     */
    @Test
    public void testIntegerZero() throws IOException {
        byte[] zero = {DERValue.tag_Integer, 0x01, 0x00};

        DEROutputStream out = new DEROutputStream();
        out.putInteger(new BigInt(BigInteger.ZERO));
        assertArrayEquals(zero, out.toByteArray());

        BigInt parsed = new DERInputStream(zero).getInteger();
        assertEquals(BigInteger.ZERO, parsed.toBigInteger());
        DEROutputStream out2 = new DEROutputStream();
        out2.putInteger(parsed);
        assertArrayEquals(zero, out2.toByteArray());

        DEROutputStream out3 = new DEROutputStream();
        out3.putInteger(new BigInt(0));
        assertArrayEquals(zero, out3.toByteArray());
    }


    /**
     * An OID with a long form length (128 or more content bytes) is read completely (N90).
     *
     * @throws IOException in case of error
     */
    @Test
    public void testLongObjectIdentifier() throws IOException {
        final int count = 129;
        final StringBuilder expected = new StringBuilder(OID_PREFIX);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(DERValue.tag_ObjectId);
        writeLength(out, count + 1);
        out.write(0x2A); // 1.2
        for (int i = 0; i < count; i++) {
            out.write(0x01);
            expected.append(".1");
        }
        byte[] encoding = out.toByteArray();

        assertEquals(expected.toString(), new DERInputStream(encoding).getOID().toString());

        // trailing data after the OID does not belong to it
        byte[] withTrailingData = new byte[encoding.length + 3];
        System.arraycopy(encoding, 0, withTrailingData, 0, encoding.length);
        withTrailingData[encoding.length] = DERValue.tag_Integer;
        withTrailingData[encoding.length + 1] = 0x01;
        withTrailingData[encoding.length + 2] = 0x07;
        DERInputStream in = new DERInputStream(withTrailingData);
        assertEquals(expected.toString(), in.getOID().toString());
        assertEquals(7, in.getInteger().toInt());

        DEROutputStream encoded = new DEROutputStream();
        encoded.putOID(new ObjectIdentifier(expected.toString()));
        assertArrayEquals(encoding, encoded.toByteArray());
    }


    /**
     * The first sub identifier of an OID is encoded in base 128, short and empty OIDs are rejected (N91).
     *
     * @throws IOException in case of error
     */
    @Test
    public void testObjectIdentifierEncoding() throws IOException {
        byte[] encoding = {DERValue.tag_ObjectId, 0x03, (byte) 0x88, 0x37, 0x03};
        DEROutputStream out = new DEROutputStream();
        out.putOID(new ObjectIdentifier("2.999.3"));
        assertArrayEquals(encoding, out.toByteArray());
        assertEquals("2.999.3", new DERInputStream(encoding).getOID().toString());

        DEROutputStream out2 = new DEROutputStream();
        out2.putOID(new ObjectIdentifier(OID_PREFIX));
        assertArrayEquals(new byte[] {DERValue.tag_ObjectId, 0x01, 0x2A}, out2.toByteArray());

        assertThrows(IllegalArgumentException.class, () -> new DEROutputStream().putOID(new ObjectIdentifier("1")));
        assertThrows(IllegalArgumentException.class, () -> new DEROutputStream().putOID(new ObjectIdentifier(new int[0])));

        byte[] emptyOID = {DERValue.tag_ObjectId, 0x00};
        assertThrows(IOException.class, () -> new DERInputStream(emptyOID).getOID());
        assertThrows(IOException.class, () -> new DERValue(new ByteArrayInputStream(emptyOID)).getOID());
    }


    /**
     * Time values with characters which are not digits or with invalid fields are rejected (N92).
     *
     * @throws IOException in case of error
     */
    @Test
    public void testTimeValues() throws IOException {
        Date utcTime = new DERInputStream(createTime(DERValue.tag_UtcTime, "990101000000Z")).getUTCTime();
        assertEquals(Date.from(Instant.parse("1999-01-01T00:00:00Z")), utcTime);
        Date generalizedTime = new DERInputStream(createTime(DERValue.tag_GeneralizedTime, "20990101000000Z")).getGeneralizedTime();
        assertEquals(Date.from(Instant.parse("2099-01-01T00:00:00Z")).getTime() / 1000, generalizedTime.getTime() / 1000);

        String[] invalidUTCTimes = {"99010100000AZ", "99010100-100Z", "9901010000-0Z", "99-101000000Z", "990100000000Z", "990001000000Z",
                                    "991301000000Z", "990101240000Z", "990101006000Z", "990101000060Z", "990101000000+01A0", "99 101000000Z"};
        for (String invalidTime : invalidUTCTimes) {
            byte[] data = createTime(DERValue.tag_UtcTime, invalidTime);
            assertThrows(IOException.class, () -> new DERInputStream(data).getUTCTime(), invalidTime);
        }

        String[] invalidGeneralizedTimes = {"2099010100000AZ", "20990101000-00Z", "2-99010100000Z", "20990100000000Z", "20991301000000Z",
                                            "20990101000000-0A00"};
        for (String invalidTime : invalidGeneralizedTimes) {
            byte[] data = createTime(DERValue.tag_GeneralizedTime, invalidTime);
            assertThrows(IOException.class, () -> new DERInputStream(data).getGeneralizedTime(), invalidTime);
        }
    }


    /**
     * The hashCode and toString of a malformed value do not throw an exception (N93).
     *
     * @throws IOException in case of error
     */
    @Test
    public void testMalformedValueHashCodeAndToString() throws IOException {
        byte[] malformedOID = {DERValue.tag_ObjectId, 0x05, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        DERValue value = new DERValue(new ByteArrayInputStream(malformedOID));
        assertEquals("[DERValue, tag = 6, malformed]", value.toString());
        assertEquals(value.hashCode(), new DERValue(new ByteArrayInputStream(malformedOID)).hashCode());

        byte[] emptyOID = {DERValue.tag_ObjectId, 0x00};
        DERValue emptyValue = new DERValue(new ByteArrayInputStream(emptyOID));
        assertDoesNotThrow(() -> emptyValue.toString());
        assertDoesNotThrow(() -> emptyValue.hashCode());
    }


    /**
     * Reading a sequence which takes up the rest of the stream does not increase the nesting depth of the stream (N97).
     *
     * @throws IOException in case of error
     */
    @Test
    public void testNestingDepthNotIncreasedOnSameStream() throws IOException {
        DERInputStream in = new DERInputStream(new byte[] {DERValue.tag_Sequence, 0x03, DERValue.tag_Integer, 0x01, 0x05});
        for (int i = 0; i < 150; i++) {
            in.reset();
            assertEquals(1, in.getSequence(1).length);
        }
    }


    /**
     * The tag order compares the tags unsigned, ignores the constructed bit and accepts empty arrays (N98).
     */
    @Test
    public void testByteArrayTagOrder() {
        ByteArrayTagOrder order = new ByteArrayTagOrder();
        assertTrue(order.compare(new byte[] {(byte) 0x80}, new byte[] {DERValue.tag_Integer}) > 0);
        assertTrue(order.compare(new byte[] {(byte) 0xA0}, new byte[] {0x40}) > 0);
        assertTrue(order.compare(new byte[] {DERValue.tag_Integer}, new byte[] {(byte) 0xC0}) < 0);
        assertEquals(0, order.compare(new byte[] {0x30}, new byte[] {0x10}));
        assertEquals(0, order.compare(new byte[0], new byte[0]));
        assertTrue(order.compare(new byte[0], new byte[] {0x00}) < 0);
        assertTrue(order.compare(new byte[] {0x00}, new byte[0]) > 0);
    }


    /**
     * Create nested indefinite-length sequences.
     *
     * @param depth the nesting depth
     * @return the encoding
     */
    private byte[] createNestedIndefiniteLength(int depth) {
        byte[] data = new byte[depth * 4];
        for (int i = 0; i < depth; i++) {
            data[2 * i] = DERValue.tag_Sequence;
            data[2 * i + 1] = (byte) 0x80;
        }
        return data;
    }


    /**
     * Create an encoded time value.
     *
     * @param tag the tag
     * @param time the time as string
     * @return the encoding
     */
    private byte[] createTime(byte tag, String time) {
        byte[] content = time.getBytes(StandardCharsets.US_ASCII);
        byte[] data = new byte[content.length + 2];
        data[0] = tag;
        data[1] = (byte) content.length;
        System.arraycopy(content, 0, data, 2, content.length);
        return data;
    }


    /**
     * Write a DER length.
     *
     * @param out the output stream
     * @param length the length
     */
    private void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 128) {
            out.write(length);
        } else if (length < 256) {
            out.write(0x81);
            out.write(length);
        } else if (length < 65536) {
            out.write(0x82);
            out.write(length >> 8);
            out.write(length & 0xff);
        } else {
            out.write(0x83);
            out.write(length >> 16);
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
        }
    }


    /**
     * An endless input stream: a header followed by zero bytes. It counts the bytes read.
     */
    private static class GeneratingInputStream extends InputStream {
        private final byte[] header;
        private long count;


        /**
         * Constructor for GeneratingInputStream
         *
         * @param header the header
         */
        GeneratingInputStream(byte[] header) {
            this.header = header.clone();
        }


        /**
         * @see java.io.InputStream#read()
         */
        @Override
        public int read() {
            int result = 0;
            if (count < header.length) {
                result = header[(int) count] & 0xff;
            }
            count++;
            return result;
        }


        /**
         * @see java.io.InputStream#read(byte[], int, int)
         */
        @Override
        public int read(byte[] b, int off, int len) {
            for (int i = 0; i < len; i++) {
                b[off + i] = 0;
                if (count + i < header.length) {
                    b[off + i] = header[(int) (count + i)];
                }
            }
            count += len;
            return len;
        }


        /**
         * Get the number of bytes read.
         *
         * @return the number of bytes read
         */
        long getCount() {
            return count;
        }
    }
}
