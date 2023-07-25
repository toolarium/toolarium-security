/*
 * DEROutputStream.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.rsa.der;

import com.github.toolarium.security.rsa.der.comparator.ByteArrayLexOrder;
import com.github.toolarium.security.rsa.der.comparator.ByteArrayTagOrder;
import com.github.toolarium.security.rsa.der.data.BigInt;
import com.github.toolarium.security.rsa.der.data.BitArray;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.TimeZone;


/**
 * Output stream marshaling DER-encoded data.  This is eventually provided in the form of a byte array; there is no advance limit on the size of
 * that byte array.
 *
 * <P>At this time, this class supports only a subset of the types of DER data encodings which are defined.  That subset is sufficient for
 * generating most X.509 certificates.
 * 
 * @author patrick
 */
public class DEROutputStream extends ByteArrayOutputStream implements DEREncoder {
    /**
     *  Lexicographical order comparison on byte arrays, for ordering
     *  elements of a SET OF objects in DER encoding.
     */
    private static ByteArrayLexOrder lexOrder = new ByteArrayLexOrder();

    
    /**
     *  Tag order comparison on byte arrays, for ordering elements of 
     *  SET objects in DER encoding.
     */
    private static ByteArrayTagOrder tagOrder = new ByteArrayTagOrder();

    
    /**
     * Construct an DER output stream.
     * 
     * @param size how large a buffer to preallocate.
     */
    public DEROutputStream(int size) {
        super(size);
    }

    
    /**
     * Construct an DER output stream.
     */
    public DEROutputStream() { 
        // NOP
    }


    /**
     * Writes tagged, pre-marshaled data. This calcuates and encodes the length, so that the output data is the standard triple of
     * { tag, length, data } used by all DER values.
     *
     * @param tag the DER value tag for the data, such as <em>DerValue.tag_Sequence</em>
     * @param b buffered data, which must be DER-encoded
     */
    public void write(byte tag, byte[] b) {
        write(tag);
        putLength(b.length);
        write(b, 0, b.length);
    }

    
    /**
     * Writes tagged data using buffer-to-buffer copy.  As above, this writes a standard DER record.  This is often used when
     * efficiently encapsulating values in sequences.
     *
     * @param tag the DER value tag for the data, such as <em>DERValue.tag_Sequence</em>
     * @param out buffered data
     */
    public void write(byte tag, DEROutputStream out) {
        write(tag);
        putLength(out.count);
        write(out.buf, 0, out.count);
    }

    
    /**
     * Writes implicitly tagged data using buffer-to-buffer copy. As above, this writes a standard DER record. This is
     * often used when efficiently encapsulating implicitly tagged values.
     * 
     * @param tag   the DER value of the context-specific tag that replaces original tag of the value in the output,
     *              such as in [field] [N] IMPLICIT [type] For example, <em>FooLength [1] IMPLICIT INTEGER</em>, with
     *              value=4; would be encoded as "81 01 04" whereas in explicit tagging it would be encoded as "A1 03 02
     *              01 04". Notice that the tag is A1 and not 81, this is because with explicit tagging the form is
     *              always constructed.
     * @param value original value being implicitly tagged
     */  
    public void writeImplicit(byte tag, DEROutputStream value) {
        write(tag);
        write(value.buf, 1, value.count - 1);
    }

    
    /**
     * Marshals pre-encoded DER value onto the output stream.
     * 
     * @param val the value
     * @exception IOException in case of error 
     */
    public void putDERValue(DERValue val) throws IOException {
        val.encode(this);
    }

    
    /*
     * PRIMITIVES -- these are "universal" ASN.1 simple types.
     *
     *  BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL
     *  OBJECT IDENTIFIER, SEQUENCE(OF), SET(OF)
     *  PrintableString, T61String, IA5String, UTCTime
     */

    
    /**
     * Marshals a DER boolean on the output stream.
     * @param val the value
     */  
    public void putBoolean(boolean val) {
        write(DERValue.tag_Boolean);
        putLength(1);
        if (val) {
            write(0xff);
        } else {
            write(0);
        }
    }

    
    /**
     * Marshals a DER unsigned integer on the output stream.
     * 
     * @param i the value
     */
    public void putInteger(BigInt i) {
        write(DERValue.tag_Integer);
        putBigInt(i);
    }

    
    /**
     * Marshals a DER enumerated on the output stream.
     * 
     * @param i the value
     */
    public void putEnumerated(BigInt i) {
        write(DERValue.tag_Enumerated);
        putBigInt(i);
    }

    
    /**
     * Put big int
     *
     * @param i the big int
     */
    private void putBigInt(BigInt i) {
        byte[] b = i.toByteArray();
        if ((b[0] & 0x080) != 0) {
            // prepend zero so it's not read as a negative number
            putLength(b.length + 1);
            write(0);
        } else {
            putLength(b.length);
        }
        write(b, 0, b.length);
    }

    
    /**
     * Marshals a DER bit string on the output stream. The bit string must be byte-aligned.
     *
     * @param bits the bit string, MSB first
     * @exception IOException in case of error 
     */
    public void putBitString(byte[] bits) throws IOException {
        write(DERValue.tag_BitString);
        putLength(bits.length + 1);
        write(0); // all of last octet is used
        write(bits);
    }

    
    /**
     * Marshals a DER bit string on the output stream. The bit strings need not be byte-aligned.
     *
     * @param b the bit string, MSB first
     * @exception IOException in case of error 
     */
    public void putUnalignedBitString(BitArray b) throws IOException {
        byte[] bits = b.toByteArray();
        write(DERValue.tag_BitString);
        putLength(bits.length + 1);
        write(bits.length * 8 - b.length()); // excess bits in last octet
        write(bits);
    }

    
    /**
     * DER-encodes an ASN.1 OCTET STRING value on the output stream.
     *
     * @param octets the octet string
     */
    public void putOctetString(byte[] octets) {
        write(DERValue.tag_OctetString, octets);
    }

    
    /**
     * Marshals a DER "null" value on the output stream.  These are often used to indicate optional values which have been omitted.
     */
    public void putNull() {
        write(DERValue.tag_Null);
        putLength(0);
    }

    
    /**
     * Marshals an object identifier (OID) on the output stream. Corresponds to the ASN.1 "OBJECT IDENTIFIER" construct.
     * @param oid the id
     */
    public void putOID(ObjectIdentifier oid) {
        oid.encode(this);
    }

    
    /**
     * Marshals a sequence on the output stream.  This supports both the ASN.1 "SEQUENCE" (zero to N values) and "SEQUENCE OF" (one to N values) constructs.
     * 
     * @param seq the sequence
     * @exception IOException in case of error 
     */
    public void putSequence(DERValue[] seq) throws IOException {
        DEROutputStream bytes = new DEROutputStream();
        int i;

        for (i = 0; i < seq.length; i++) {
            seq[i].encode(bytes);
        }

        write(DERValue.tag_Sequence, bytes);
    }

    
    /**
     * Marshals the contents of a set on the output stream without ordering the elements.  Ok for BER encoding, but not for DER encoding. 
     * For DER encoding, use orderedPutSet() or orderedPutSetOf().
     *  
     * @param set the values
     * @exception IOException in case of error 
     */
    public void putSet(DERValue[] set) throws IOException {
        DEROutputStream bytes = new DEROutputStream();
        int i;

        for (i = 0; i < set.length; i++) {
            set[i].encode(bytes);
        }

        write(DERValue.tag_Set, bytes);
    }

    
    /**
     * Marshals the contents of a set on the output stream.  Sets are semantically unordered, but DER requires that encodings of
     * set elements be sorted into ascending lexicographical order before being output.  Hence sets with the same tags and
     * elements have the same DER encoding.
     * This method supports the ASN.1 "SET OF" construct, but not "SET", which uses a different order.
     *   
     * @param tag the tag
     * @param set the set
     * @exception IOException in case of error 
     */
    public void putOrderedSetOf(byte tag, DEREncoder[] set) throws IOException {
        putOrderedSet(tag, set, lexOrder);
    }

    
    /**
     * Marshals the contents of a set on the output stream.  Sets are semantically unordered, but DER requires that encodings of
     * set elements be sorted into ascending tag order before being output.  Hence sets with the same tags and
     * elements have the same DER encoding.
     * This method supports the ASN.1 "SET" construct, but not "SET OF", which uses a different order.
     *   
     * @param tag the tag
     * @param set the set
     * @exception IOException in case of error 
     */
    public void putOrderedSet(byte tag, DEREncoder[] set) throws IOException {
        putOrderedSet(tag, set, tagOrder);
    }
    
    
    /**
     * Marshals a the contents of a set on the output stream with the 
     * encodings of its sorted in increasing order.
     *
     * @param tag the tag
     * @param set the set
     * @param order the order to use when sorting encodings of components.
     * @throws IOException In case of a data error 
     */
    private void putOrderedSet(byte tag, DEREncoder[] set, Comparator<byte[]> order) throws IOException {
        DEROutputStream[] streams = new DEROutputStream[set.length];

        for (int i = 0; i < set.length; i++) {
            streams[i] = new DEROutputStream();
            set[i].derEncode(streams[i]);
        }

        // order the element encodings
        byte[][] bufs = new byte[streams.length][];

        for (int i = 0; i < streams.length; i++) {
            bufs[i] = streams[i].toByteArray();
        }
        Arrays.sort(bufs, order);

        DEROutputStream bytes = new DEROutputStream();
        for (int i = 0; i < streams.length; i++) {
            bytes.write(bufs[i]);
        }
        write(tag, bytes);
    }

    
    /**
     * Marshals a string as a DER encoded UTF8String.
     * 
     * @param s the string
     * @exception IOException in case of error 
     */
    public void putUTF8String(String s) throws IOException {
        writeString(s, DERValue.tag_UTF8String, "UTF8");
    }

    
    /**
     * Marshals a string as a DER encoded PrintableString.
     * 
     * @param s the string
     * @exception IOException in case of error 
     */
    public void putPrintableString(String s) throws IOException {
        writeString(s, DERValue.tag_PrintableString, "ASCII");
    }

    
    /**
     * Marshals a string as a DER encoded T61String.
     * 
     * @param s the string
     * @exception IOException in case of error 
     */
    public void putT61String(String s) throws IOException {
        /*
         * Works for characters that are defined in both ASCII and T61.
         */
        writeString(s, DERValue.tag_T61String, "ASCII");
    }    

    
    /**
     * Marshals a string as a DER encoded IA5String.
     * 
     * @param s the string
     * @exception IOException in case of error 
     */
    public void putIA5String(String s) throws IOException {
        writeString(s, DERValue.tag_IA5String, "ASCII");
    }

    
    /**
     * Marshals a string as a DER encoded BMPString.
     * 
     * @param s the string
     * @exception IOException in case of error 
     */
    public void putBMPString(String s) throws IOException {
        writeString(s, DERValue.tag_BMPString, "UnicodeBigUnmarked");
    }

    
    /**
     * Private helper routine for writing DER encoded string values.
     * 
     * @param s the string to write
     * @param stringTag one of the DER string tags that indicate which encoding should be used to write the string out.
     * @param enc the name of the encoder that should be used corresponding to the above tag.
     * @throws IOException In case of a data eror 
     */
    private void writeString(String s, byte stringTag, String enc) throws IOException {
        byte[] data = s.getBytes(enc);

        write(stringTag);
        putLength(data.length);
        write(data);
    }

    
    /**
     * Marshals a DER UTC time/date value.
     *
     * <P>YYMMDDhhmmss{Z|+hhmm|-hhmm} ... emits only using Zulu time
     * and with seconds (even if seconds=0) as per RFC 2459.
     * @param d the date
     * @exception IOException in case of error 
     */
    public void putUTCTime(Date d) throws IOException {
        // * Format the date.
        TimeZone tz = TimeZone.getTimeZone("GMT");
        String pattern = "yyMMddHHmmss'Z'";
        SimpleDateFormat sdf = new SimpleDateFormat(pattern);
        sdf.setTimeZone(tz);
        byte[] utc = (sdf.format(d)).getBytes();

        // Write the formatted date.
        write(DERValue.tag_UtcTime);
        putLength(utc.length);
        write(utc);
    }


    /**
     * Marshals a DER Generalized Time/date value.
     *   
     * <P>YYYYMMDDhhmmss{Z|+hhmm|-hhmm} ... emits only using Zulu time and with seconds (even if seconds=0) as per RFC 2459.
     * @param d the date
     * @exception IOException in case of error 
     */  
    public void putGeneralizedTime(Date d) throws IOException {
        // Format the date.
        TimeZone tz = TimeZone.getTimeZone("GMT");
        String pattern = "yyyyMMddHHmmss'Z'";
        SimpleDateFormat sdf = new SimpleDateFormat(pattern);

        sdf.setTimeZone(tz);
        byte[] gt = (sdf.format(d)).getBytes();

        // Write the formatted date.
        write(DERValue.tag_GeneralizedTime);
        putLength(gt.length);
        write(gt);
    }


    /**
     * Put the encoding of the length in the stream.
     *   
     * @param len the length of the attribute.
     */  
    public void putLength(int len) {
        if (len < 128) {
            write((byte) len);

        } else if (len < (1 << 8)) {
            write((byte) 0x081);
            write((byte) len);

        } else if (len < (1 << 16)) {
            write((byte) 0x082);
            write((byte) (len >> 8));
            write((byte) len);

        } else if (len < (1 << 24)) {
            write((byte) 0x083);
            write((byte) (len >> 16));
            write((byte) (len >> 8));
            write((byte) len);

        } else {
            write((byte) 0x084);
            write((byte) (len >> 24));
            write((byte) (len >> 16));
            write((byte) (len >> 8));
            write((byte) len);
        }
    }

    
    /**
     * Put the tag of the attribute in the stream.
     *   
     * @param tagClass the tag class type, one of UNIVERSAL, CONTEXT, APPLICATION or PRIVATE
     * @param form if true, the value is constructed, otherwise it is primitive.
     * @param val the tag value
     */  
    public void putTag(byte tagClass, boolean form, byte val) {
        byte tag = (byte) (tagClass | val);

        if (form) {
            tag |= (byte) 0x20;
        }
        write(tag);
    }

    
    /**
     * Write the current contents of this <code>DerOutputStream</code> to an <code>OutputStream</code>.
     *
     * @param out the stream
     * @exception IOException on output error.
     */
    @Override
    public void derEncode(OutputStream out) throws IOException {
        out.write(toByteArray());
    }
}

