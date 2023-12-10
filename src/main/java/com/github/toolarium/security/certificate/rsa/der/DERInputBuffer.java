/*
 * DERInputBuffer.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.rsa.der;

import com.github.toolarium.security.certificate.rsa.der.data.BigInt;
import com.github.toolarium.security.certificate.rsa.der.data.BitArray;
import java.io.ByteArrayInputStream;
import java.io.IOException;


/**
 * DER input buffer ... this is the main abstraction in the DER library
 * which actively works with the "untyped byte stream" abstraction.  It
 * does so with impunity, since it's not intended to be exposed to 
 * anyone who could violate the "typed value stream" DER model and hence
 * corrupt the input stream of DER values.
 * 
 * @author patrick
 */
public class DERInputBuffer extends ByteArrayInputStream implements Cloneable {
    /**
     * Constructor for DerInputBuffer
     * 
     * @param buf the buffer
     */
    public DERInputBuffer(byte[] buf) {
        super(buf);
    }

    
    /**
     * Constructor for DERInputBuffer
     *
     * @param buf the buffer
     * @param offset the offset
     * @param len the length 
     */
    DERInputBuffer(byte[] buf, int offset, int len) {
        super(buf, offset, len);
    }

    
    /**
     * Duplicate 
     *
     * @return the buffer
     * @throws IllegalArgumentException In case of invalid argument
     */
    public DERInputBuffer dup() throws IllegalArgumentException {
        try {
            DERInputBuffer retval = (DERInputBuffer) clone();
            retval.mark(Integer.MAX_VALUE);
            return retval;
        } catch (CloneNotSupportedException e) {
            throw new IllegalArgumentException(e.toString());
        }
    }

    
    /**
     * To byte array
     *
     * @return the byte array
     */
    byte[] toByteArray() {
        int len = available();

        if (len <= 0) {
            return null;
        }
        
        byte[] retval = new byte[len];
        System.arraycopy(buf, pos, retval, 0, len);
        return retval;
    }

    
    /**
     * Peek 
     *
     * @return the current byte
     * @throws IOException In case of missing data
     */
    int peek() throws IOException {
        if (pos >= count) {
            throw new IOException("out of data");
        }
        return buf[pos];
    }

    
    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object other) {
        if (other instanceof DERInputBuffer) {
            return equals((DERInputBuffer) other);
        }
        
        return false;
    }

    
    /**
     * Compare an object 
     *
     * @param other the object to compar
     * @return true if they are equals
     */
    boolean equals(DERInputBuffer other) {
        if (this == other) {
            return true;
        }

        int max = this.available();
        if (other.available() != max) {
            return false;
        }
        
        for (int i = 0; i < max; i++) {
            if (this.buf[this.pos + i] != other.buf[other.pos + i]) {
                return false;
            }
        }
        return true;
    }

    
    /**
     * Returns a hashcode for this DerInputBuffer.
     *
     * @return a hashcode for this DerInputBuffer.
     */
    @Override
    public int hashCode() {
        int retval = 0;

        int len = available();
        int p = pos;

        for (int i = 0; i < len; i++) {
            retval += buf[p + i] * i;
        }
        return retval;
    }

    
    /**
     * Truncate 
     *
     * @param len the length
     * @throws IOException In case of missing data
     */
    public void truncate(int len) throws IOException {
        if (len > available()) {
            throw new IOException("insufficient data");
        }
        count = pos + len;
    }

    
    /**
     * Returns the unsigned integer which takes up the specified number of bytes in this buffer.
     * 
     * @param l the length
     * @return the integer
     * @throws IOException In case of missing data
     */
    public BigInt getUnsigned(int l) throws IOException {
        int len = l;
        if (len > available()) {
            throw new IOException("short read of integer/enumerated");
        }

        /*
         * A prepended zero is used to ensure that the integer is interpreted as unsigned even when the high order bit is
         * zero.  We don't support signed BigInts.
         *
         * Fix this here ... BigInts aren't expected to have these, and stuff like signing (sigsize = f(modulus)) misbehaves.
         */
        if (buf[pos] == 0) {
            len--;
            skip(1);
        }

        /*
         * Consume the rest of the buffer, returning its value as
         * an unsigned integer.
         */
        byte[] bytes = new byte[len];

        System.arraycopy(buf, pos, bytes, 0, len);
        skip(len);
        return new BigInt(bytes);
    }


    /**
     * Returns the bit string which takes up the rest of this buffer. This bit string must be byte-aligned.
     * 
     * @return the byte array
     */
    public byte[] getBitString() {
        if (pos >= count || buf[pos] != 0) {
            return null;
        }

        /*
         * Just copy the data into an aligned, padded octet buffer,
         * and consume the rest of the buffer.
         */
        int len = available();
        byte[] retval = new byte[len - 1];

        System.arraycopy(buf, pos + 1, retval, 0, len - 1);
        pos = count;
        return retval;
    }


    /**
     * Returns the bit string which takes up the rest of this buffer. The bit string need not be byte-aligned.
     * 
     * @return the bit array
     */
    public BitArray getUnalignedBitString() {
        if (pos >= count) {
            return null;
        }

        /*
         * Just copy the data into an aligned, padded octet buffer,
         * and consume the rest of the buffer.
         */
        int len = available();
        byte[] bits = new byte[len - 1];
        int length = bits.length * 8 - buf[pos]; // number of valid bits

        System.arraycopy(buf, pos + 1, bits, 0, len - 1);
        BitArray bitArray = new BitArray(length, bits);
        pos = count;
        return bitArray;
    }
}


