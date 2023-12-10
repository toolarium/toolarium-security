/*
 * BitArray.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.rsa.der.data;

import java.io.ByteArrayOutputStream;


/**
 * A packed array of booleans.
 * 
 * @author patrick
 */
public class BitArray {
    private static final byte[][] NYBBLE = {{(byte)'0', (byte)'0', (byte)'0', (byte)'0'}, 
                                            {(byte)'0', (byte)'0', (byte)'0', (byte)'1'}, 
                                            {(byte)'0', (byte)'0', (byte)'1', (byte)'0'}, 
                                            {(byte)'0', (byte)'0', (byte)'1', (byte)'1'}, 
                                            {(byte)'0', (byte)'1', (byte)'0', (byte)'0'}, 
                                            {(byte)'0', (byte)'1', (byte)'0', (byte)'1'}, 
                                            {(byte)'0', (byte)'1', (byte)'1', (byte)'0'}, 
                                            {(byte)'0', (byte)'1', (byte)'1', (byte)'1'}, 
                                            {(byte)'1', (byte)'0', (byte)'0', (byte)'0'}, 
                                            {(byte)'1', (byte)'0', (byte)'0', (byte)'1'}, 
                                            {(byte)'1', (byte)'0', (byte)'1', (byte)'0'}, 
                                            {(byte)'1', (byte)'0', (byte)'1', (byte)'1'}, 
                                            {(byte)'1', (byte)'1', (byte)'0', (byte)'0'}, 
                                            {(byte)'1', (byte)'1', (byte)'0', (byte)'1'}, 
                                            {(byte)'1', (byte)'1', (byte)'1', (byte)'0'}, 
                                            {(byte)'1', (byte)'1', (byte)'1', (byte)'1'} };
    
    private static final int BYTES_PER_LINE = 8;
    private static final int BITS_PER_UNIT = 8;
    private byte[] repn;
    private int length;

    
    /**
     * Creates a BitArray of the specified size, initialized to zeros.
     * 
     * @param length the length
     * @exception IllegalArgumentException in case of error
     */
    public BitArray(int length) throws IllegalArgumentException {
        if (length < 0) {
            throw new IllegalArgumentException("Negative length for BitArray");
        }
        
        this.length = length;
        repn = new byte[(length + BITS_PER_UNIT - 1) / BITS_PER_UNIT]; 
    }


    /**
     * Creates a BitArray of the specified size, initialized from the specified byte array.  The most significant bit of a[0] gets
     * index zero in the BitArray.  The array a must be large enough to specify a value for every bit in the BitArray.  In other words,
     * 8*a.length &lt;= length.
     * 
     * @param length the length
     * @param a the array
     * @exception IllegalArgumentException in case of error
     */
    public BitArray(int length, byte[] a) throws IllegalArgumentException {
        if (length < 0) {
            throw new IllegalArgumentException("Negative length for BitArray");
        }
        
        if (a.length * BITS_PER_UNIT < length) {
            throw new IllegalArgumentException("Byte array too short to represent bit array of given length");
        }
        
        this.length = length;
        int repLength = ((length + BITS_PER_UNIT - 1) / BITS_PER_UNIT);
        int unusedBits = repLength * BITS_PER_UNIT - length;
        byte bitMask = (byte) (0xFF << unusedBits);

        /*
         normalize the representation:
         1. discard extra bytes
         2. zero out extra bits in the last byte
         */
        repn = new byte[repLength]; 
        System.arraycopy(a, 0, repn, 0, repLength);
        repn[repn.length - 1] = (byte) (repn[repn.length - 1] & bitMask);
    }


    /**
     * Create a BitArray whose bits are those of the given array of Booleans. 
     * @param bits the bits
     */
    public BitArray(boolean[] bits) {
        length = bits.length;
        repn = new byte[(length + 7) / 8];

        for (int i = 0; i < length; i++) {
            set(i, bits[i]);
        }
    }
        
    
    /**
     * Copy constructor (for cloning).
     * 
     * @param ba the array 
     */
    private BitArray(BitArray ba) {
        length = ba.length;
        repn = ba.repn.clone();
    }

    
    /**
     * Returns the indexed bit in this BitArray.
     * 
     * @param index the index
     * @return the value
     * @exception ArrayIndexOutOfBoundsException in case of error
     */
    public boolean get(int index) throws ArrayIndexOutOfBoundsException {
        if (index < 0 || index >= length) {
            throw new ArrayIndexOutOfBoundsException(Integer.toString(index));
        }
        
        return (repn[subscript(index)] & position(index)) != 0;
    }

    
    /**
     * Sets the indexed bit in this BitArray.
     * 
     * @param index the index
     * @param value the value to set
     * @exception ArrayIndexOutOfBoundsException in case of error
     */
    public void set(int index, boolean value) throws ArrayIndexOutOfBoundsException {
        if (index < 0 || index >= length) {
            throw new ArrayIndexOutOfBoundsException(Integer.toString(index));
        }

        int idx = subscript(index);
        int bit = position(index);

        if (value) {
            repn[idx] |= bit;
        } else {
            repn[idx] &= ~bit;
        }
    }

    
    /**
     * Returns the length of this BitArray.
     * 
     * @return the length
     */
    public int length() {
        return length;
    }

    
    /**
     * Returns a Byte array containing the contents of this BitArray. The bit stored at index zero in this BitArray will be copied
     * into the most significant bit of the zeroth element of the returned byte array.  The last byte of the returned byte array
     * will be contain zeros in any bits that do not have corresponding bits in the BitArray.  (This matters only if the BitArray's size
     * is not a multiple of 8.)
     * @return the array
     */ 
    public byte[] toByteArray() {
        return repn.clone();
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (obj == null || !(obj instanceof BitArray)) {
            return false;
        }

        BitArray ba = (BitArray) obj;
        if (ba.length != length) {
            return false;
        }

        for (int i = 0; i < repn.length; i += 1) {
            if (repn[i] != ba.repn[i]) {
                return false;
            }
        }

        return true;
    }

    
    /**
     * Return a boolean array with the same bit values a this BitArray.
     * 
     * @return the boolean array
     */
    public boolean[] toBooleanArray() {
        boolean[] bits = new boolean[length];

        for (int i = 0; i < length; i++) {
            bits[i] = get(i);
        }
        
        return bits;
    }

    
    /**
     * Returns a hash code value for this bit array.
     * 
     * @return  a hash code value for this bit array.
     */
    @Override
    public int hashCode() {
        int hashCode = 0;

        for (int i = 0; i < repn.length; i++) {
            hashCode = 31 * hashCode + repn[i];
        }

        return hashCode ^ length;
    }

    
    /**
     * @see java.lang.Object#clone()
     */
    @Override
    public Object clone() {
        return new BitArray(this);
    }

    
    /**
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        for (int i = 0; i < repn.length - 1; i++) {
            out.write(NYBBLE[(repn[i] >> 4) & 0x0F], 0, 4);
            out.write(NYBBLE[repn[i] & 0x0F], 0, 4);

            if (i % BYTES_PER_LINE == BYTES_PER_LINE - 1) {
                out.write('\n');
            } else {
                out.write(' ');
            }
        }

        // in last byte of repn, use only the valid bits
        for (int i = BITS_PER_UNIT * (repn.length - 1); i < length; i++) {
            if (get(i)) { // out.write(get(i) ? '1' : '0');
                out.write('1');
            } else {
                out.write('0');
            }
            
        }

        return new String(out.toByteArray());
    }

    
    /**
     * Subscript
     * 
     * @param idx the index
     * @return the subscript
     */
    private static int subscript(int idx) {
        return idx / BITS_PER_UNIT;
    }

    
    /**
     * Gets the position
     * 
     * @param idx the index
     * @return the position
     */
    private static int position(int idx) {
        // bits big-endian in each unit
        return 1 << (BITS_PER_UNIT - 1 - (idx % BITS_PER_UNIT));
    }
}
