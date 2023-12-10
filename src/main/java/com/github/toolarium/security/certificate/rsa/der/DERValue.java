/*
 * DERValue.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.rsa.der;

import com.github.toolarium.security.certificate.rsa.der.data.BigInt;
import com.github.toolarium.security.certificate.rsa.der.data.BitArray;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * Represents a single DER-encoded value.  DER encoding rules are a subset of the "Basic" Encoding Rules (BER), but they only support a single way
 * ("Definite" encoding) to encode any given value.
 *
 * <P>All DER-encoded data are triples <em>{type, length, data}</em>.  This class represents such tagged values as they have been read (or constructed),
 * and provides structured access to the encoded data.
 *
 * <P>At this time, this class supports only a subset of the types of DER data encodings which are defined.  That subset is sufficient for parsing
 * most X.509 certificates, and working with selected additional formats (such as PKCS #10 certificate requests, and some kinds of PKCS #7 data).
 * 
 * @author patrick
 */
public class DERValue {

    /** Tag value indicating an ASN.1 "BOOLEAN" value. */
    public static final byte tag_Boolean = 0x01;

    /** Tag value indicating an ASN.1 "INTEGER" value. */
    public static final byte tag_Integer = 0x02;

    /** Tag value indicating an ASN.1 "BIT STRING" value. */
    public static final byte tag_BitString = 0x03;

    /** Tag value indicating an ASN.1 "OCTET STRING" value. */
    public static final byte tag_OctetString = 0x04;

    /** Tag value indicating an ASN.1 "NULL" value. */
    public static final byte tag_Null = 0x05;

    /** Tag value indicating an ASN.1 "OBJECT IDENTIFIER" value. */
    public static final byte tag_ObjectId = 0x06;

    /** Tag value including an ASN.1 "ENUMERATED" value */
    public static final byte tag_Enumerated = 0x0A;

    /** Tag value indicating an ASN.1 "UTF8String" value. */
    public static final byte tag_UTF8String = 0x12;

    /** Tag value including a "printable" string */
    public static final byte tag_PrintableString = 0x13;

    /** Tag value including a "teletype" string */
    public static final byte tag_T61String = 0x14;

    /** Tag value including an ASCII string */
    public static final byte tag_IA5String = 0x16;

    /** Tag value indicating an ASN.1 "UTCTime" value. */
    public static final byte tag_UtcTime = 0x17;

    /** Tag value indicating an ASN.1 "GeneralizedTime" value. */
    public static final byte tag_GeneralizedTime = 0x18;

    /** Tag value indicating an ASN.1 "UniversalString" value. */
    public static final byte tag_UniversalString = 0x1C;

    /** Tag value indicating an ASN.1 "BMPString" value. */
    public static final byte tag_BMPString = 0x1E;

    // CONSTRUCTED seq/set

    /** Tag value indicating an ASN.1
     * "SEQUENCE" (zero to N elements, order is significant). */
    public static final byte tag_Sequence = 0x30;

    /** Tag value indicating an ASN.1
     * "SEQUENCE OF" (one to N elements, order is significant). */
    public static final byte tag_SequenceOf = 0x30;

    /** Tag value indicating an ASN.1
     * "SET" (zero to N members, order does not matter). */
    public static final byte tag_Set = 0x31;

    /** Tag value indicating an ASN.1
     * "SET OF" (one to N members, order does not matter). */
    public static final byte tag_SetOf = 0x31;

    /** The tag class types */
    public static final byte TAG_UNIVERSAL = (byte)0x000;
    
    /** the application tag */
    public static final byte TAG_APPLICATION = (byte)0x040;
    
    /** the context tag */
    public static final byte TAG_CONTEXT = (byte)0x080;
    
    /** the private tag */
    public static final byte TAG_PRIVATE = (byte)0x0c0;

    private static final String QUOTATION_MARKS = "\"";

    /** The DER tag of the value; one of the tag_ constants. */
    private byte tag;

    /** The DER-encoded data of the value. */
    private DERInputStream data;
    
    private DERInputBuffer buffer;
    private int length;

    
    /**
     * Creates a PrintableString DER value from a string
     * 
     * @param value the value
     */
    public DERValue(String value) {
        tag = tag_PrintableString;
        length = value.length();

        int i;
        byte[] buf = new byte[length];

        for (i = 0; i < length; i++) {
            buf[i] = (byte) value.charAt(i);
        }
        
        buffer = new DERInputBuffer(buf);
        data = new DERInputStream(buffer);
        data.mark(Integer.MAX_VALUE);
    }

    
    /**
     * Creates a DERValue from a tag and some DER-encoded data.
     *
     * @param tag the DER type tag
     * @param data the DER-encoded data
     */
    public DERValue(byte tag, byte[] data) {
        this.tag = tag;
        buffer = new DERInputBuffer(data.clone());
        length = data.length;
        this.data = new DERInputStream(buffer);
        this.data.mark(Integer.MAX_VALUE);
    }

    
    /**
     * package private
     * 
     * @param i buffer
     * @throws IOException In case of a data error
     */
    DERValue(DERInputBuffer i) throws IOException {
        // xxx must also parse BER-encoded constructed values such as sequences, sets...
        DERInputBuffer in = i;
        
        tag = (byte)in.read();
        length = DERInputStream.getLength(in);
        if (length == -1) { // indefinite length encoding found
            in.reset();      // reset position to beginning of the stream
            byte[] indefData = new byte[in.available()];
            DataInputStream dis = new DataInputStream(in);

            dis.readFully(indefData);
            dis.close();
            DERIndefLenConverter derIn = new DERIndefLenConverter();

            in = new DERInputBuffer(derIn.convert(indefData));
            if (tag != in.read()) {
                throw new IOException("Indefinite length encoding not supported");
            }
            
            length = DERInputStream.getLength(in);
        }

        buffer = in.dup();
        buffer.truncate(length);
        data = new DERInputStream(buffer);
        in.skip(length);
    }


    /**
     * Get an ASN1/DER encoded datum from an input stream.  The stream may have additional data following the encoded datum.
     * In case of indefinite length encoded datum, the input stream must hold only one datum.
     *
     * @param in the input stream holding a single DER datum, which may be followed by additional data
     * @exception IOException in case of error
     */
    public DERValue(InputStream in) throws IOException {
        init(false, in);
    }

    
    /*
     * The type starts at the first byte of the encoding, and
     * is one of these tag_* values.  That may be all the type
     * data that is needed.
     */

    /*
     * These tags are the "universal" tags ... they mean the same
     * in all contexts.  (Mask with 0x1f -- five bits.)
     */

    /**
     * These values are the high order bits for the other kinds of tags.
     * 
     * @return true if it is universal 
     */
    boolean isUniversal() {
        return ((tag & 0x0c0) == 0x000);
    }

    /**
     * Is application
     *
     * @return true it it is an application
     */
    boolean isApplication() {
        return ((tag & 0x0c0) == 0x040);
    }

    /**
     * Returns true iff the CONTEXT SPECIFIC bit is set in the type tag. This is associated with the ASN.1 "DEFINED BY" syntax.
     * @return result
     */
    public boolean isContextSpecific() {
        return ((tag & 0x0c0) == 0x080);
    }

    
    /**
     * Returns true iff the CONTEXT SPECIFIC TAG matches the passed tag.
     * 
     * @param cntxtTag the tag
     * @return result
     */
    public boolean isContextSpecific(byte cntxtTag) {
        if (!isContextSpecific()) {
            return false;
        }
        return ((tag & 0x01f) == cntxtTag);
    }

    
    /**
     * Is private 
     *
     * @return true if it is private
     */
    boolean isPrivate() {
        return ((tag & 0x0c0) == 0x0c0);
    }

    
    /** 
     * Returns true iff the CONSTRUCTED bit is set in the type tag.
     * 
     * @return result
     */
    public boolean isConstructed() {
        return ((tag & 0x020) == 0x020);
    }

    
    /**
     * helper routine
     * 
     * @param fullyBuffered  true if it is fully buffered
     * @param i the input stream
     * @throws IOException In case of a data error
     */
    private void init(boolean fullyBuffered, InputStream i) throws IOException {
        InputStream in = i;
        tag = (byte) in.read();
        byte lenByte = (byte) in.read();

        length = DERInputStream.getLength((lenByte & 0xff), in);
        if (length == -1) {
            // indefinite length encoding found
            int readLen = in.available();
            int offset = 2; // for tag and length bytes
            byte[] indefData = new byte[readLen + offset];

            indefData[0] = tag;
            indefData[1] = lenByte;
            DataInputStream dis = new DataInputStream(in);

            dis.readFully(indefData, offset, readLen);
            dis.close();
            DERIndefLenConverter derIn = new DERIndefLenConverter();

            in = new ByteArrayInputStream(derIn.convert(indefData));
            if (tag != in.read()) {
                throw new IOException("Indefinite length encoding not supported");
            }
            
            length = DERInputStream.getLength(in);
        }

        if (length == 0) {
            return;
        }
        
        if (fullyBuffered && in.available() != length) {
            throw new IOException("Extra data given to DERValue constructor");
        }
        
        byte[] bytes = new byte[length];

        // n.b. readFully not needed in normal fullyBuffered case
        DataInputStream dis = new DataInputStream(in);

        dis.readFully(bytes);
        buffer = new DERInputBuffer(bytes);
        data = new DERInputStream(buffer);
    }


    /**
     * Encode an ASN1/DER encoded datum onto a DER output stream.
     * 
     * @param out the stream
     * @exception IOException in case of error
     */
    public void encode(DEROutputStream out) throws IOException {
        out.write(tag);
        out.putLength(length);

        // xxx yeech, excess copies ... DERInputBuffer.write(OutStream)
        if (length > 0) {
            byte[] value = new byte[length];
            buffer.reset();

            if (buffer.read(value) != length) {
                throw new IOException("short DER value read (encode)");
            }

            out.write(value);
        }
    }

    
    /**
     * Returns an ASN.1 BOOLEAN
     *
     * @return the boolean held in this DER value
     * @exception IOException in case of error
     */
    public boolean getBoolean() throws IOException {
        if (tag != tag_Boolean) {
            throw new IOException("DerValue.getBoolean, not a BOOLEAN " + tag);
        }
        if (length != 1) {
            throw new IOException("DERValue.getBoolean, invalid length " + length);
        }
        if (buffer.read() != 0) {
            return true;
        }
        return false;
    }

    
    /**
     * Returns an ASN.1 OBJECT IDENTIFIER.
     *
     * @return the OID held in this DER value
     * @exception IOException in case of error
     */
    public ObjectIdentifier getOID() throws IOException {
        if (tag != tag_ObjectId) {
            throw new IOException("DERValue.getOID, not an OID " + tag);
        }
        return new ObjectIdentifier(buffer);
    }


    /**
     * Returns an ASN.1 OCTET STRING
     *
     * @return the octet string held in this DER value
     * @exception IOException in case of error
     */
    public byte[] getOctetString() throws IOException {
        if (tag != tag_OctetString) {
            throw new IOException("DERValue.getOctetString, not an Octet String: " + tag);
        }

        byte[] bytes = new byte[length];
        if (buffer.read(bytes) != length) {
            throw new IOException("short read on DERValue buffer");
        }
        
        return bytes;
    }

    
    /**
     * Returns an ASN.1 unsigned INTEGER value.
     *
     * @return the (unsigned) integer held in this DER value
     * @exception IOException in case of error
     */
    public BigInt getInteger() throws IOException {
        if (tag != tag_Integer) {
            throw new IOException("DERValue.getInteger, not an int " + tag);
        }
        
        return buffer.getUnsigned(data.available());
    }

    
    /**
     * Returns an ASN.1 unsigned INTEGER value, the parameter determining if the tag is implicit.
     *
     * @param tagImplicit if true, ignores the tag value as it is assumed implicit.
     * @return the (unsigned) integer held in this DER value
     * @exception IOException in case of error
     */
    public BigInt getInteger(boolean tagImplicit) throws IOException {
        if (!tagImplicit) {
            if (tag != tag_Integer) {
                throw new IOException("DERValue.getInteger, not an int " + tag);
            }
        }
        return buffer.getUnsigned(data.available());
    }

    
    /**
     * Returns an ASN.1 ENUMERATED value.
     *
     * @return the integer held in this DER value
     * @exception IOException in case of error
     */
    public BigInt getEnumerated() throws IOException { 
        if (tag != tag_Enumerated) {
            throw new IOException("DERValue.getEnumerated, incorrect tag: " + tag);
        }
        
        return buffer.getUnsigned(data.available());
    }

    
    /**
     * Returns an ASN.1 BIT STRING value.  The bit string must be byte-aligned.
     *
     * @return the bit string held in this value
     * @exception IOException in case of error
     */
    public byte[] getBitString() throws IOException {
        if (tag != tag_BitString) {
            throw new IOException("DERValue.getBitString, not a bit string " + tag);
        }
        
        return buffer.getBitString();
    }

    
    /**
     * Returns an ASN.1 BIT STRING value, with the tag assumed implicit based on the parameter.  The bit string must be byte-aligned.
     *
     * @param tagImplicit if true, the tag is assumed implicit.
     * @return the bit string held in this value
     * @exception IOException in case of error
     */
    public byte[] getBitString(boolean tagImplicit) throws IOException {
        if (!tagImplicit) {
            if (tag != tag_BitString) {
                throw new IOException("DERValue.getBitString, not a bit string " + tag);
            }
        }
        
        return buffer.getBitString();
    }

    
    /**
     * Returns an ASN.1 BIT STRING value that need not be byte-aligned.
     *
     * @return a BitArray representing the bit string held in this value
     * @exception IOException in case of error
     */
    public BitArray getUnalignedBitString() throws IOException {
        if (tag != tag_BitString) {
            throw new IOException("DERValue.getBitString, not a bit string " + tag);
        }
        
        return buffer.getUnalignedBitString();
    }

    
    /**
     * Returns an ASN.1 BIT STRING value, with the tag assumed implicit based on the parameter.  The bit string need not be byte-aligned.
     *
     * @param tagImplicit if true, the tag is assumed implicit.
     * @return the bit string held in this value
     * @exception IOException in case of error
     */
    public BitArray getUnalignedBitString(boolean tagImplicit) throws IOException {
        if (!tagImplicit) {
            if (tag != tag_BitString) {
                throw new IOException("DERValue.getBitString, not a bit string " + tag);
            }
        }
        return buffer.getUnalignedBitString();
    }

    
    /**
     * Returns the name component as a Java string, regardless of its encoding restrictions (ASCII, T61, Printable, IA5, BMP, UTF8).
     * 
     * @return the string
     * @exception IOException in case of error
     */
    // TBD: Need encoder for UniversalString before it can be handled.
    public String getAsString() throws IOException {
        if (tag == tag_UTF8String) {
            return getUTF8String();
        } else if (tag == tag_PrintableString) {
            return getPrintableString();
        } else if (tag == tag_T61String) { 
            return getT61String();
        } else if (tag == tag_IA5String) {
            return getIA5String();
        /*
         * } else if (tag == tag_UniversalString) return getUniversalString() {
         */
        } else if (tag == tag_BMPString) {
            return getBMPString();
        } else {
            return null;
        }
    }

    
    /**
     * Helper routine to return all the bytes contained in the DERInputStream associated with this object.
     * 
     * @return the array
     * @throws IOException In case of a data error
     */
    private byte[] getDataBytes() throws IOException {
        byte[] retVal = new byte[length];
        data.reset();
        data.getBytes(retVal);
        return retVal;
    }

    
    /**
     * Returns an ASN.1 STRING value
     *
     * @return the printable string held in this value
     * @exception IOException in case of error
     */
    public String getPrintableString() throws IOException {
        if (tag != tag_PrintableString) {
            throw new IOException("DERValue.getPrintableString, not a string " + tag);
        }

        return new String(getDataBytes(), "ASCII");
    }

    
    /**
     * Returns an ASN.1 T61 (Teletype) STRING value
     *
     * @return the teletype string held in this value
     * @exception IOException in case of error
     */
    public String getT61String() throws IOException {
        if (tag != tag_T61String) {
            throw new IOException("DERValue.getT61String, not T61 " + tag);
        }

        /*
         * Works for characters that are defined in both ASCII and T61.
         */
        return new String(getDataBytes(), "ASCII");
    }

    
    /**
     * Returns an ASN.1 IA5 (ASCII) STRING value
     *
     * @return the ASCII string held in this value
     * @exception IOException in case of error
     */
    public String getIA5String() throws IOException {
        if (tag != tag_IA5String) {
            throw new IOException("DERValue.getIA5String, not IA5 " + tag);
        }

        return new String(getDataBytes(), "ASCII");
    }

    
    /**
     * Returns the ASN.1 BMP (Unicode) STRING value as a Java string.
     *
     * @return a string corresponding to the encoded BMPString held in this value
     * @exception IOException in case of error
     */
    public String getBMPString() throws IOException {
        if (tag != tag_BMPString) {
            throw new IOException("DERValue.getBMPString, not BMP " + tag);
        }
        
        // BMPString is the same as Unicode in big endian, unmarked format.
        return new String(getDataBytes(), "UnicodeBigUnmarked");
    }

    
    /**
     * Returns the ASN.1 UTF-8 STRING value as a Java String.
     *
     * @return a string corresponding to the encoded UTF8String held in this value
     * @exception IOException in case of error
     */
    public String getUTF8String() throws IOException {
        if (tag != tag_UTF8String) {
            throw new IOException("DERValue.getUTF8String, not UTF-8 " + tag);
        }

        return new String(getDataBytes(), "UTF8");
    }

    
    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object other) {
        if (other instanceof DERValue) {
            return equals((DERValue) other);
        }
        return false;
    }

    
    /**
     * Bitwise equality comparison.  DER encoded values have a single encoding, so that bitwise equality of the encoded values is an
     * efficient way to establish equivalence of the unencoded values.
     *
     * @param other the object being compared with this one
     * @return true if they are the equals
     */
    public boolean equals(DERValue other) {
        data.reset();
        other.data.reset();
        if (this == other) {
            return true;
        } else if (tag != other.tag) {
            return false;
        } else {
            return buffer.equals(other.buffer);
        }
    }

    
    /**
     * Returns a printable representation of the value.
     *
     * @return printable representation of the value
     */
    @Override
    public String toString() {
        try {
            if (tag == tag_UTF8String) {
                return QUOTATION_MARKS + getUTF8String() + QUOTATION_MARKS;
            }
            if (tag == tag_PrintableString) {
                return QUOTATION_MARKS + getPrintableString() + QUOTATION_MARKS;
            }
            if (tag == tag_T61String) {
                return QUOTATION_MARKS + getT61String() + QUOTATION_MARKS;
            }
            if (tag == tag_IA5String) {
                return QUOTATION_MARKS + getIA5String() + QUOTATION_MARKS;
            }
            /*
             // TBD: Need encoder for UniversalString before it can
             // be handled.
             if (tag == tag_UniversalString)
             return "\"" + getUniversalString() + "\"";
             */
            if (tag == tag_BMPString) {
                return QUOTATION_MARKS + getBMPString() + QUOTATION_MARKS;
            }
            if (tag == tag_Null) {
                return "[DERValue, null]";
            }
            if (tag == tag_ObjectId) {
                return "OID." + getOID();
            }

            // integers
            return "[DERValue, tag = " + tag + ", length = " + length + "]";
        } catch (IOException e) {
            throw new IllegalArgumentException("misformatted DER value");
        }
    }


    /**
     * Returns a DER-encoded value, such that if it's passed to the DERValue constructor, a value equivalent to "this" is returned.
     *
     * @return DER-encoded value, including tag and length.
     * @exception IOException in case of error
     */
    public byte[] toByteArray() throws IOException {
        DEROutputStream out = new DEROutputStream();

        encode(out);
        data.reset();
        return out.toByteArray();
    }

    /**
     * For "set" and "sequence" types, this function may be used to return a DER stream of the members of the set or sequence.
     * This operation is not supported for primitive types such as integers or bit strings.
     * @return the stream
     * @exception IOException in case of error
     */
    public DERInputStream toDERInputStream() throws IOException {
        if (tag == tag_Sequence || tag == tag_Set) {
            return new DERInputStream(buffer);
        }
        
        throw new IOException("toDerInputStream rejects tag type " + tag);
    }

    
    /**
     * Get the length of the encoded value.
     * 
     * @return the length
     */
    public int length() {
        return length;
    }

    
    /**
     * Create the tag of the attribute.
     *
     * @param tagClass the tag class type, one of UNIVERSAL, CONTEXT, APPLICATION or PRIVATE
     * @param form if true, the value is constructed, otherwise it is primitive.
     * @param val the tag value
     * @return the created byte
     */
    public static byte createTag(byte tagClass, boolean form, byte val) {
        byte t = (byte) (tagClass | val);

        if (form) {
            t |= (byte) 0x20;
        }

        return t;
    }

    /**
     * Set the tag of the attribute. Commonly used to reset the
     * tag value used for IMPLICIT encodings.
     *
     * @param t the tag value
     */
    public void resetTag(byte t) {
        this.tag = t;
    }

    /**
     * Returns a hashcode for this DERValue.
     * @return a hashcode for this DERValue.
     */
    @Override
    public int hashCode() {
        return toString().hashCode();
    }
}

