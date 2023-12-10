/*
 * DERInputStream.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.rsa.der;

import com.github.toolarium.security.certificate.rsa.der.data.BigInt;
import com.github.toolarium.security.certificate.rsa.der.data.BitArray;
import java.io.IOException;
import java.io.InputStream;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.Vector;


/**
 * A DER input stream, used for parsing ASN.1 DER-encoded data such as that found in X.509 certificates.  DER is a subset of BER/1, which has
 * the advantage that it allows only a single encoding of primitive data. (High level data such as dates still support many encodings.)  That is,
 * it uses the "Definite" Encoding Rules (DER) not the "Basic" ones (BER).
 *
 * <P>Note that, like BER/1, DER streams are streams of explicitly tagged data values.  Accordingly, this programming interface does
 * not expose any variant of the java.io.InputStream interface, since that kind of input stream holds untagged data values and using that
 * I/O model could prevent correct parsing of the DER data.
 *
 * <P>At this time, this class supports only a subset of the types of DER data encodings which are defined.  That subset is sufficient for parsing
 * most X.509 certificates.
 * 
 * @author patrick
 */
public class DERInputStream {
    
    // This version only supports fully buffered DER.  This is easy to work with, though if large objects are manipulated DER becomes
    // awkward to deal with.  That's where BER is useful, since BER handles streaming data relatively well.
    private DERInputBuffer buffer;

    
    /**
     * Create a DER input stream from a data buffer. The buffer is not copied, it is shared.  Accordingly, the buffer should be treated
     * as read-only.
     *
     * @param data the buffer from which to create the string (CONSUMED)
     */
    public DERInputStream(byte[] data) {
        init(data, 0, data.length);
    }

    
    /**
     * Create a DER input stream from part of a data buffer. The buffer is not copied, it is shared.  Accordingly, the
     * buffer should be treated as read-only.
     *
     * @param data the buffer from which to create the string (CONSUMED)
     * @param offset the first index of <em>data</em> which will be read as DER input in the new stream
     * @param len how long a chunk of the buffer to use, starting at "offset"
     */
    public DERInputStream(byte[] data, int offset, int len) {
        init(data, offset, len);
    }

    
    /**
     * Constructor for DERInputStream
     * 
     * @param buf the buffer
     */
    public DERInputStream(DERInputBuffer buf) {
        buffer = buf;
        buffer.mark(Integer.MAX_VALUE);
    }

    
    /**
     * Creates a new DER input stream from part of this input stream.
     *
     * @param len how long a chunk of the current input stream to use, starting at the current position.
     * @param doSkip true if the existing data in the input stream should be skipped. If this value is false, the next data read
     *          on this stream and the newly created stream will be the same.
     * @return the stream
     * @exception IOException in case of error
     */
    public DERInputStream subStream(int len, boolean doSkip) throws IOException {
        DERInputBuffer newbuf = buffer.dup();

        newbuf.truncate(len);
        if (doSkip) {
            buffer.skip(len);
        }
        
        return new DERInputStream(newbuf);
    }

    
    /**
     * Return what has been written to this DERInputStream as a byte array. Useful for debugging.
     * @return the array
     */
    public byte[] toByteArray() {
        return buffer.toByteArray();
    }

    
    /*
     * PRIMITIVES -- these are "universal" ASN.1 simple types.
     *
     *  INTEGER, ENUMERATED, BIT STRING, OCTET STRING, NULL
     *  OBJECT IDENTIFIER, SEQUENCE (OF), SET (OF)
     *  UTF8String, PrintableString, T61String, IA5String, UTCTime,
     *  GeneralizedTime, BMPString.
     * Note: UniversalString not supported till encoder is available.
     */

    
    /**
     * Get an (unsigned) integer from the input stream.
     * 
     * @return the integer
     * @exception IOException in case of error
     */
    public BigInt getInteger() throws IOException {
        if (buffer.read() != DERValue.tag_Integer) {
            throw new IOException("DER input, Integer tag error");
        }

        return buffer.getUnsigned(getLength(buffer));
    }

    
    /**
     * Get an enumerated from the input stream.
     * 
     * @return the integer
     * @exception IOException in case of error
     */
    public BigInt getEnumerated() throws IOException {
        if (buffer.read() != DERValue.tag_Enumerated) {
            throw new IOException("DER input, Enumerated tag error");
        }

        return buffer.getUnsigned(getLength(buffer));
    }

    
    /**
     * Get a bit string from the input stream.  Only octet-aligned bitstrings (multiples of eight bits in length) are handled by this method.
     * 
     * @return the array
     * @exception IOException in case of error
     */
    public byte[] getBitString() throws IOException {
        if (buffer.read() != DERValue.tag_BitString) {
            throw new IOException("DER input not an bit string");
        }
        
        int length = getLength(buffer);

        // This byte affects alignment and padding (for the last byte). Use getUnalignedBitString() for none 8-bit aligned bit strings.
        if (buffer.read() != 0) {
            throw new IOException("unaligned bit string");
        }
        
        length--;

        // Just read the data into an aligned, padded octet buffer.
        byte[] retval = new byte[length];
        if (buffer.read(retval) != length) {
            throw new IOException("short read of DER bit string");
        }
        return retval;
    }


    /**
     * Get a bit string from the input stream.  The bit string need not be byte-aligned.
     * 
     * @return the array
     * @exception IOException in case of error
     */
    public BitArray getUnalignedBitString() throws IOException {
        if (buffer.read() != DERValue.tag_BitString) {
            throw new IOException("DER input not a bit string");
        }
        
        int length = getLength(buffer) - 1;

        // First byte = number of excess bits in the last octet of the representation.
        int validBits = length * 8 - buffer.read();
        byte[] repn = new byte[length];
        if (buffer.read(repn) != length) {
            throw new IOException("short read of DER bit string");
        }
        return new BitArray(validBits, repn);
    }


    /**
     * Returns an ASN.1 OCTET STRING from the input stream.
     * 
     * @return the array
     * @exception IOException in case of error
     */
    public byte[] getOctetString() throws IOException {
        if (buffer.read() != DERValue.tag_OctetString) {
            throw new IOException("DER input not an octet string");
        }

        int length = getLength(buffer);
        byte[] retval = new byte[length];
        if (buffer.read(retval) != length) {
            throw new IOException("short read of DER octet string");
        }

        return retval;
    }

    
    /**
     * Returns the asked number of bytes from the input stream.
     * 
     * @param val the array
     * @exception IOException in case of error
     */
    public void getBytes(byte[] val) throws IOException {
        if (buffer.read(val) != val.length) {
            throw new IOException("short read of DER octet string");
        }
    }

    
    /**
     * Reads an encoded null value from the input stream.
     * 
     * @exception IOException in case of error
     */
    public void getNull() throws IOException {
        if (buffer.read() != DERValue.tag_Null || buffer.read() != 0) {
            throw new IOException("getNull, bad data");
        }
    }

    
    /**
     * Reads an X.200 style Object Identifier from the stream.
     * 
     * @return the id
     * @exception IOException in case of error
     */
    public ObjectIdentifier getOID() throws IOException {
        return new ObjectIdentifier(this);
    }

    
    /**
     * Return a sequence of encoded entities.  ASN.1 sequences are ordered, and they are often used, like a "struct" in C or C++,
     * to group data values.  They may have optional or context specific values.
     *
     * @param startLen guess about how long the sequence will be (used to initialize an auto-growing data structure)
     * @return array of the values in the sequence
     * @exception IOException in case of error
     */
    public DERValue[] getSequence(int startLen) throws IOException {
        if (buffer.read() != DERValue.tag_Sequence) {
            throw new IOException("Sequence tag error");
        }
        
        return readVector(startLen);
    }

    
    /**
     * Return a set of encoded entities.  ASN.1 sets are unordered, though DER may specify an order for some kinds of sets (such
     * as the attributes in an X.500 relative distinguished name) to facilitate binary comparisons of encoded values.
     *
     * @param startLen guess about how large the set will be (used to initialize an auto-growing data structure)
     * @return array of the values in the sequence
     * @exception IOException in case of error
     */
    public DERValue[] getSet(int startLen) throws IOException {
        if (buffer.read() != DERValue.tag_Set) {
            throw new IOException("Set tag error");
        }
        
        return readVector(startLen);
    }

    
    /**
     * Return a set of encoded entities.  ASN.1 sets are unordered, though DER may specify an order for some kinds of sets (such
     * as the attributes in an X.500 relative distinguished name) to facilitate binary comparisons of encoded values.
     *
     * @param startLen guess about how large the set will be (used to initialize an auto-growing data structure)
     * @param implicit if true tag is assumed implicit.
     * @return array of the values in the sequence
     * @exception IOException in case of error
     */
    public DERValue[] getSet(int startLen, boolean implicit) throws IOException {
        int tag = buffer.read();

        if (!implicit) {
            if (tag != DERValue.tag_Set) {
                throw new IOException("Set tag error");
            }
        }
        return (readVector(startLen));
    }

    
    /**
     * Read a "vector" of values ... set or sequence have the same encoding, except for the initial tag, so both use
     * this same helper routine.
     * 
     * @param startLen the start length
     * @return the DERValue's
     * @throws IOException In case of a data error
     */
    protected DERValue[] readVector(int startLen) throws IOException {
        int len = getLength(buffer);
        DERInputStream newstr;

        if (len == 0) { // return empty array instead of null, which should be used only for missing optionals
            return new DERValue[0];
        }
        
        // Create a temporary stream from which to read the data, unless it's not really needed.
        if (buffer.available() == len) {
            newstr = this;
        } else {
            newstr = subStream(len, true);
        }
        
        // Pull values out of the stream.
        Vector<DERValue> vec = new Vector<DERValue>(startLen, 5);
        DERValue value;

        do {
            value = new DERValue(newstr.buffer);
            vec.addElement(value);
        } while (newstr.available() > 0);

        if (newstr.available() != 0) {
            throw new IOException("extra data at end of vector");
        }
        
        // Now stick them into the array we're returning.
        int max = vec.size();
        DERValue[] retval = new DERValue[max];
        for (int i = 0; i < max; i++) {
            retval[i] = vec.elementAt(i);
        }

        return retval;
    }

    
    /**
     * Get a single DER-encoded value from the input stream. It can often be useful to pull a value from the stream
     * and defer parsing it.  For example, you can pull a nested sequence out with one call, and only examine its elements
     * later when you really need to.
     * 
     * @return the value
     * @exception IOException in case of error
     */
    public DERValue getDERValue() throws IOException {
        return new DERValue(buffer);
    }

    
    /**
     * Read a string that was encoded as a UTF8String DER value.
     * 
     * @return the string
     * @exception IOException in case of error
     */
    public String getUTF8String() throws IOException {
        return readString(DERValue.tag_UTF8String, "UTF-8", "UTF8");
    }

    
    /**
     * Read a string that was encoded as a PrintableString DER value.
     * 
     * @return the string
     * @exception IOException in case of error
     */
    public String getPrintableString() throws IOException {
        return readString(DERValue.tag_PrintableString, "Printable", "ASCII");
    }

    
    /**
     * Read a string that was encoded as a T61String DER value.
     * 
     * @return the string
     * @exception IOException in case of error
     */
    public String getT61String() throws IOException {
        return readString(DERValue.tag_T61String, "T61", "ASCII"); // Works for common characters between T61 and ASCII.
    }


    /**
     * Read a string that was encoded as a IA5tring DER value.
     * 
     * @return the string
     * @exception IOException in case of error
     */
    public String getIA5String() throws IOException {
        return readString(DERValue.tag_IA5String, "IA5", "ASCII");
    }

    
    /**
     * Read a string that was encoded as a BMPString DER value.
     * 
     * @return the string
     * @exception IOException in case of error
     */
    public String getBMPString() throws IOException {
        return readString(DERValue.tag_BMPString, "BMP", "UnicodeBigUnmarked");
    }
    
    
    /**
     * Get a UTC encoded time value from the input stream.
     * 
     * @return the date
     * @exception IOException in case of error
     */
    public Date getUTCTime() throws IOException {
        if (buffer.read() != DERValue.tag_UtcTime) {
            throw new IOException("DER input, UTCtime tag invalid ");
        }
        if (buffer.available() < 11) {
            throw new IOException("DER input, UTCtime short input");
        }

        int len = getLength(buffer);
        if (len < 11 || len > 17) {
            throw new IOException("DER getUTCTime length error");
        }

        // UTC time encoded as ASCII chars, YYMMDDhhmmss. If YY <= 50, we assume 20YY; if YY > 50, we assume 19YY, as per RFC 2459.
        int year = 10 * Character.digit((char) buffer.read(), 10);
        year += Character.digit((char) buffer.read(), 10);
        if (year <= 50) { // origin 2000
            year += 2000;
        } else {
            year += 1900;   // origin 1900
        }

        int month = 10 * Character.digit((char) buffer.read(), 10);
        month += Character.digit((char) buffer.read(), 10);
        month -= 1; // months are 0-11

        int day = 10 * Character.digit((char) buffer.read(), 10);
        day += Character.digit((char) buffer.read(), 10);

        int hour = 10 * Character.digit((char) buffer.read(), 10);
        hour += Character.digit((char) buffer.read(), 10);

        int minute = 10 * Character.digit((char) buffer.read(), 10);
        minute += Character.digit((char) buffer.read(), 10);

        len -= 10;

        // We allow for non-encoded seconds, even though the IETF-PKIX specification says that the seconds should always be encoded even if it is zero.
        int second;
        if (len == 3 || len == 7) {
            second = 10 * Character.digit((char) buffer.read(), 10);
            second += Character.digit((char) buffer.read(), 10);
            len -= 2;
        } else {
            second = 0;
        }

        if (month < 0 || day <= 0
            || month > 11 || day > 31 || hour >= 24
            || minute >= 60 || second >= 60) {
            throw new IOException("Parse UTC time, invalid format");
        }

        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        cal.set(year, month, day, hour, minute, second);
        cal.set(Calendar.ERA, GregorianCalendar.AD);
        Date readDate = cal.getTime();
        long utcTime = (readDate.getTime() / 1000) * 1000;

        
        // Finally, "Z" or "+hhmm" or "-hhmm" ... offsets change hhmm
        if (!(len == 1 || len == 5)) {
            throw new IOException("Parse UTC time, invalid offset");
        }

        int htmp;
        int mtmp;
        switch (buffer.read()) {
            case '+': 
                htmp = 10 * Character.digit((char) buffer.read(), 10);
                htmp += Character.digit((char) buffer.read(), 10);
                mtmp = 10 * Character.digit((char) buffer.read(), 10);
                mtmp += Character.digit((char) buffer.read(), 10);
                if (htmp >= 24 || mtmp >= 60) {
                    throw new IOException("Parse UTCtime, +hhmm");
                }

                utcTime += ((htmp * 60) + mtmp) * 60 * 1000;
                break;

            case '-': 
                htmp = 10 * Character.digit((char) buffer.read(), 10);
                htmp += Character.digit((char) buffer.read(), 10);
                mtmp = 10 * Character.digit((char) buffer.read(), 10);
                mtmp += Character.digit((char) buffer.read(), 10);
                if (htmp >= 24 || mtmp >= 60) {
                    throw new IOException("Parse UTCtime, -hhmm");
                }
                utcTime -= ((htmp * 60) + mtmp) * 60 * 1000;
                break;

            case 'Z':
                break;

            default:
                throw new IOException("Parse UTCtime, garbage offset");
        }
        readDate.setTime(utcTime);
        return readDate;
    }


    /**
     * Get a generalized encoded time value from the input stream.
     * 
     * @return the date
     * @exception IOException in case of error
     */
    public Date getGeneralizedTime() throws IOException {
        if (buffer.read() != DERValue.tag_GeneralizedTime) {
            throw new IOException("DER input, GeneralizedTime tag invalid ");
        }
        
        if (buffer.available() < 13) {
            throw new IOException("DER input, GeneralizedTime short input");
        }
        
        int len = getLength(buffer); // CHECKSTYLE IGNORE THIS LINE

        // Generalized time encoded as ASCII chars, YYYYMMDDhhmm[ss]
        int year = 1000 * Character.digit((char) buffer.read(), 10);
        year += 100 * Character.digit((char) buffer.read(), 10);
        year += 10 * Character.digit((char) buffer.read(), 10);
        year += Character.digit((char) buffer.read(), 10);

        int month = 10 * Character.digit((char) buffer.read(), 10);
        month += Character.digit((char) buffer.read(), 10);
        month -= 1; // Calendar months are 0-11

        int day = 10 * Character.digit((char) buffer.read(), 10);
        day += Character.digit((char) buffer.read(), 10);

        int hour = 10 * Character.digit((char) buffer.read(), 10);
        hour += Character.digit((char) buffer.read(), 10);

        int minute = 10 * Character.digit((char) buffer.read(), 10);
        minute += Character.digit((char) buffer.read(), 10);

        len -= 12;

        // We allow for non-encoded seconds, even though the IETF-PKIX specification says that the seconds should always be encoded even if it is zero.
        int second;
        if (len == 3 || len == 7) {
            second = 10 * Character.digit((char) buffer.read(), 10);
            second += Character.digit((char) buffer.read(), 10);
            len -= 2;
        } else {
            second = 0;
        }

        if (month < 0 || day <= 0
                || month > 11 || day > 31 || hour >= 24
                || minute >= 60 || second >= 60) {
            throw new IOException("Parse Generalized time, invalid format");
        }

        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        cal.set(year, month, day, hour, minute, second);
        cal.set(Calendar.ERA, GregorianCalendar.AD);
        Date readDate = cal.getTime();
        long utcTime = readDate.getTime();

        // Finally, "Z" or "+hhmm" or "-hhmm" ... offsets change hhmm
        if (!(len == 1 || len == 5)) {
            throw new IOException("Parse Generalized time, invalid offset");
        }

        int htmp;
        int mtmp;
        switch (buffer.read()) {
            case '+':
                htmp = 10 * Character.digit((char) buffer.read(), 10);
                htmp += Character.digit((char) buffer.read(), 10);
                mtmp = 10 * Character.digit((char) buffer.read(), 10);
                mtmp += Character.digit((char) buffer.read(), 10);
                if (htmp >= 24 || mtmp >= 60) {
                    throw new IOException("Parse GeneralizedTime, +hhmm");
                }

                utcTime += ((htmp * 60) + mtmp) * 60 * 1000;
                break;

            case '-':
                htmp = 10 * Character.digit((char) buffer.read(), 10);
                htmp += Character.digit((char) buffer.read(), 10);
                mtmp = 10 * Character.digit((char) buffer.read(), 10);
                mtmp += Character.digit((char) buffer.read(), 10);

                if (htmp >= 24 || mtmp >= 60) {
                    throw new IOException("Parse GeneralizedTime, -hhmm");
                }
                
                utcTime -= ((htmp * 60) + mtmp) * 60 * 1000;
                break;

            case 'Z':
                break;

            default:
                throw new IOException("Parse GeneralizedTime, garbage offset");
        }
        readDate.setTime(utcTime);
        return readDate;
    }

    
    /**
     * Mark the current position in the buffer, so that a later call to <code>reset</code> will return here.
     * 
     * @param value the value
     */
    public void mark(int value) {
        buffer.mark(value);
    }

    
    /**
     * Return to the position of the last <code>mark</code> call.  A mark is implicitly set at the beginning of the stream when it is created.
     */
    public void reset() {
        buffer.reset();
    }

    
    /**
     * Returns the number of bytes available for reading. This is most useful for testing whether the stream is empty.
     * 
     * @return the available bytes
     */
    public int available() {
        return buffer.available();
    }    
    
    
    /**
     * Peek a byte
     * 
     * @return the byte
     * @throws IOException in case of error
     */
    public int peekByte() throws IOException {
        return buffer.peek();
    }    
    
    
    /**
     * Initialize the data
     * 
     * @param data the data
     * @param offset the offset
     * @param len the length
     */
    private void init(byte[] data, int offset, int len) {
        // check for indefinite length encoding
        if (DERIndefLenConverter.isIndefinite(data[offset + 1])) {
            try {
                byte[] inData = new byte[len];
                System.arraycopy(data, offset, inData, 0, len);
                DERIndefLenConverter derIn = new DERIndefLenConverter();
                buffer = new DERInputBuffer(derIn.convert(inData));
            } catch (IOException ioe) {
                // NOP
            }
        } else {
            buffer = new DERInputBuffer(data, offset, len);
        }
        buffer.mark(Integer.MAX_VALUE);
    }

    
    /**
     * Private helper routine to read an encoded string from the input stream.
     * 
     * @param stringTag the tag for the type of string to read
     * @param stringName a name to display in error messages
     * @param enc the encoder to use to interpret the data. Should correspond to the stringTag above.
     * @return the string
     * @throws IOException In case of a data error
     */
    private String readString(byte stringTag, String stringName, String enc) throws IOException {
        if (buffer.read() != stringTag) {
            throw new IOException("DER input not a " + stringName + " string");
        }

        int length = getLength(buffer);
        byte[] retval = new byte[length];

        if (buffer.read(retval) != length) {
            throw new IOException("short read of DER " + stringName + " string");
        }

        return new String(retval, enc);
    }

    
    /**
     * Get a byte from the input stream.
     * 
     * @return a byte
     */
    public int getByte() {
        return (0x00ff & buffer.read());
    }

    
    /**
     * Gets the length
     * 
     * @return the length
     * @throws IOException in case of error
     */
    public int getLength() throws IOException {
        return getLength(buffer);
    }

    
    /**
     * Get a length from the input stream, allowing for at most 32 bits of encoding to be used.  (Not the same as getting a tagged integer!)
     * 
     * @param in the input stream
     * @return the length or -1 if indefinite length found.
     * @exception IOException on parsing error or unsupported lengths.
     */
    public static int getLength(InputStream in) throws IOException {
        return getLength(in.read(), in);
    }

    
    /**
     * Get a length from the input stream, allowing for at most 32 bits of encoding to be used.  (Not the same as getting a tagged integer!)
     * 
     * @param lenByte the length
     * @param in the input stream
     * @return the length or -1 if indefinite length found.
     * @exception IOException on parsing error or unsupported lengths.
     */
    public static int getLength(int lenByte, InputStream in) throws IOException {
        int value;
        int tmp = lenByte;
        if ((tmp & 0x080) == 0x00) { // short form, 1 byte datum
            value = tmp;
        } else { // long form or indefinite
            tmp &= 0x07f;

            /// NOTE:  tmp == 0 indicates indefinite length encoded data. tmp > 4 indicates more than 4Gb of data.
            if (tmp == 0) {
                return -1;
            }
            
            if (tmp < 0 || tmp > 4) {
                String detail = "too big.";
                if (tmp < 0) {
                    detail = "incorrect DER encoding.";
                }
                throw new IOException("DERInputStream.getLength(): lengthTag=" + tmp + ", " + detail);
            }

            for (value = 0; tmp > 0; tmp--) {
                value <<= 8;
                value += 0x0ff & in.read();
            }
        }
        return value;
    }
}

