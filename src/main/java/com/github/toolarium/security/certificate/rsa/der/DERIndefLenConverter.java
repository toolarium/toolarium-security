/*
 * DERIndefLenConverter.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.rsa.der;

import java.io.IOException;
import java.util.ArrayList;


/**
 * A package private utility class to convert indefinite length DER encoded byte arrays to definite length DER encoded byte arrays.
 * This assumes that the basic data structure is "tag, length, value" triplet. In the case where the length is "indefinite", terminating
 * end-of-contents bytes are expected.
 * 
 * @author patrick
 */
public class DERIndefLenConverter {
    private static final int TAG_MASK = 0x1f; // bits 5-1
    private static final int FORM_MASK = 0x20; // bits 6
    private static final int CLASS_MASK = 0xC0; // bits 8 and 7

    private static final int LEN_LONG = 0x80; // bit 8 set
    private static final int LEN_MASK = 0x7f; // bits 7 - 1

    private byte[] data;
    private byte[] newData;
    private int newDataPos;
    private int dataPos;
    private int dataSize;
    private int index;

    private ArrayList<Object> ndefsList = new ArrayList<Object>();
    private int numOfTotalLenBytes = 0;

    
    /**
     * Default package private constructor
     */
    public DERIndefLenConverter() {
        // NOP
    }

    /**
     * Test eoc
     *
     * @param tag the tag
     * @return true
     */
    private boolean isEOC(int tag) {
        return (((tag & TAG_MASK) == 0x00)        // EOC
                && ((tag & FORM_MASK) == 0x00)    // primitive
                && ((tag & CLASS_MASK) == 0x00)); // universal
    }

    
    /**
     * if bit 8 is set then it implies either indefinite length or long form
     *
     * @param lengthByte the length
     * @return true if the byte is of Indefinite form otherwise returns false.
     */
    static boolean isLongForm(int lengthByte) {
        return ((lengthByte & LEN_LONG) == LEN_LONG);
    }

    /**
     * Checks whether the given length byte is of the form <em>Indefinite</em>.
     *
     * @param lengthByte the length byte from a DER encoded object.
     * @return true if the byte is of Indefinite form otherwise returns false.
     */
    static boolean isIndefinite(int lengthByte) {
        return (isLongForm(lengthByte) && ((lengthByte & LEN_MASK) == 0));
    }

    
    /**
     * Parse the tag and if it is an end-of-contents tag then add the current position to the <code>eocList</code> vector.
     * 
     * @throws IOException In case of a data error
     */
    private void parseTag() throws IOException {
        if (dataPos == dataSize) {
            return;
        }
        if (isEOC(data[dataPos]) && (data[dataPos + 1] == 0)) {
            int numOfEncapsulatedLenBytes = 0;
            Object elem = null;
            int idx;

            for (idx = ndefsList.size() - 1; idx >= 0; idx--) {
                // Determine the first element in the vector that does not
                // have a matching EOC
                elem = ndefsList.get(idx);
                if (elem instanceof Integer) {
                    break;
                }
                numOfEncapsulatedLenBytes += ((byte[])elem).length - 3;
            }
            
            if (elem == null || idx < 0) {
                throw new IOException("EOC does not have matching indefinite-length tag");
            }
            int sectionLen = dataPos - ((Integer) elem).intValue() + numOfEncapsulatedLenBytes;
            byte[] sectionLenBytes = getLengthBytes(sectionLen);

            ndefsList.set(idx, sectionLenBytes);

            // Add the number of bytes required to represent this section to the total number of length bytes,
            // and subtract the indefinite-length tag (1 byte) and EOC bytes (2 bytes) for this section
            numOfTotalLenBytes += (sectionLenBytes.length - 3);
        }
        dataPos++;
    }


    /**
     * Write the tag and if it is an end-of-contents tag then skip the tag and its 1 byte length of zero.
     */
    private void writeTag() {
        if (dataPos == dataSize) {
            return;
        }
        
        int tag = data[dataPos++];
        if (isEOC(tag) && (data[dataPos] == 0)) {
            dataPos++; // skip length
            writeTag();
        } else {
            newData[newDataPos++] = (byte) tag;
        }
    }

    /**
     * Parse the length and if it is an indefinite length then add the current position to the <code>ndefsList</code> vector.
     * 
     * @return the length
     * @throws IOException In case of a data error
     */
    private int parseLength() throws IOException {
        int curLen = 0;

        if (dataPos == dataSize) {
            return curLen;
        }
        
        int lenByte = data[dataPos++] & 0xff;

        if (isIndefinite(lenByte)) {
            ndefsList.add(Integer.valueOf(dataPos));
            return curLen;
        }

        if (isLongForm(lenByte)) {
            lenByte &= LEN_MASK;
            if (lenByte > 4) {
                throw new IOException("Too much data");
            }
            
            if ((dataSize - dataPos) < (lenByte + 1)) {
                throw new IOException("Too little data");
            }
            
            for (int i = 0; i < lenByte; i++) {
                curLen = (curLen << 8) + (data[dataPos++] & 0xff);
            }
        } else {
            curLen = (lenByte & LEN_MASK);
        }

        return curLen;
    }
    
    /**
     * Write the length and if it is an indefinite length then calculate the definite length from the positions
     * of the indefinite length and its matching EOC terminator. Then, write the value.
     */
    private void writeLengthAndValue() {
        if (dataPos == dataSize) {
            return;
        }

        int curLen = 0;
        int lenByte = data[dataPos++] & 0xff;

        if (isIndefinite(lenByte)) {
            byte[] lenBytes = (byte[]) ndefsList.get(index++);

            System.arraycopy(lenBytes, 0, newData, newDataPos, lenBytes.length);
            newDataPos += lenBytes.length;
            return;
        }

        if (isLongForm(lenByte)) {
            lenByte &= LEN_MASK;
            for (int i = 0; i < lenByte; i++) {
                curLen = (curLen << 8) + (data[dataPos++] & 0xff);
            }
        } else {
            curLen = (lenByte & LEN_MASK);
        }

        writeLength(curLen);
        writeValue(curLen);
    }

    /**
     * Write bytes
     *
     * @param curLen the current length
     */
    private void writeLength(int curLen) {
        if (curLen < 128) {
            newData[newDataPos++] = (byte) curLen;
        } else if (curLen < (1 << 8)) {
            newData[newDataPos++] = (byte) 0x81;
            newData[newDataPos++] = (byte) curLen;
        } else if (curLen < (1 << 16)) {
            newData[newDataPos++] = (byte) 0x82;
            newData[newDataPos++] = (byte) (curLen >> 8);
            newData[newDataPos++] = (byte) curLen;
        } else if (curLen < (1 << 24)) {
            newData[newDataPos++] = (byte) 0x83;
            newData[newDataPos++] = (byte) (curLen >> 16);
            newData[newDataPos++] = (byte) (curLen >> 8);
            newData[newDataPos++] = (byte) curLen;
        } else {
            newData[newDataPos++] = (byte) 0x84;
            newData[newDataPos++] = (byte) (curLen >> 24);
            newData[newDataPos++] = (byte) (curLen >> 16);
            newData[newDataPos++] = (byte) (curLen >> 8);
            newData[newDataPos++] = (byte) curLen;
        }
    }

    
    /**
     * Get bytes
     *
     * @param curLen the current length
     * @return the bytes
     */
    private byte[] getLengthBytes(int curLen) {
        byte[] lenBytes;
        int idx = 0;

        if (curLen < 128) {
            lenBytes = new byte[1];
            lenBytes[idx++] = (byte) curLen;
        } else if (curLen < (1 << 8)) {
            lenBytes = new byte[2];
            lenBytes[idx++] = (byte) 0x81;
            lenBytes[idx++] = (byte) curLen;
        } else if (curLen < (1 << 16)) {
            lenBytes = new byte[3];
            lenBytes[idx++] = (byte) 0x82;
            lenBytes[idx++] = (byte) (curLen >> 8);
            lenBytes[idx++] = (byte) curLen;
        } else if (curLen < (1 << 24)) {
            lenBytes = new byte[4];
            lenBytes[idx++] = (byte) 0x83;
            lenBytes[idx++] = (byte) (curLen >> 16);
            lenBytes[idx++] = (byte) (curLen >> 8);
            lenBytes[idx++] = (byte) curLen;
        } else {
            lenBytes = new byte[5];
            lenBytes[idx++] = (byte) 0x84;
            lenBytes[idx++] = (byte) (curLen >> 24);
            lenBytes[idx++] = (byte) (curLen >> 16);
            lenBytes[idx++] = (byte) (curLen >> 8);
            lenBytes[idx++] = (byte) curLen;
        }

        return lenBytes;
    }

    
    /**
     * Parse the value;
     * 
     * @param curLen the length
     */
    private void parseValue(int curLen) {
        dataPos += curLen;
    }

    
    /**
     * Write the value;
     * 
     * @param curLen the length
     */
    private void writeValue(int curLen) {
        for (int i = 0; i < curLen; i++) {
            newData[newDataPos++] = data[dataPos++];
        }
    }

    
    /**
     * Converts a indefinite length DER encoded byte array to a definte length DER encoding.
     *
     * @param indefData the byte array holding the indefinite length encoding.
     * @return the byte array containing the definite length DER encoding.
     * @exception IOException on parsing or re-writing errors.
     */
    public byte[] convert(byte[] indefData) throws IOException {
        data = indefData;
        dataPos = 0;
        index = 0;
        dataSize = data.length;
        int len = 0;

        // parse and set up the vectors of all the indefinite-lengths
        while (dataPos < dataSize) {
            parseTag();
            len = parseLength();
            parseValue(len);
        }

        newData = new byte[dataSize + numOfTotalLenBytes];
        dataPos = 0;
        newDataPos = 0;
        index = 0;

        // write out the new byte array replacing all the indefinite-lengths
        // and EOCs
        while (dataPos < dataSize) {
            writeTag();
            writeLengthAndValue();
        }

        return newData;
    }
}
