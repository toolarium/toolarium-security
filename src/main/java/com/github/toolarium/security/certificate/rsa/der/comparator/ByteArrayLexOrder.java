/*
 * ByteArrayLexOrder.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.rsa.der.comparator;

import java.util.Comparator;


/**
 * Compare two byte arrays in lexicographical order.
 * 
 * @author patrick
 */
public class ByteArrayLexOrder implements Comparator<byte[]> {
    
    /**
     * Perform lexicographical comparison of two byte arrays, regarding each byte as unsigned.  That is, compare array entries 
     * in order until they differ--the array with the smaller entry is "smaller". If array entries are 
     * equal till one array ends, then the longer array is "bigger".
     *
     * @param bytes1 first byte array to compare.
     * @param bytes2 second byte array to compare.
     * @return negative number if obj1 &lt; obj2, 0 if obj1 == obj2, positive number if obj1 &gt; obj2.  
     */
    @Override
    public final int compare(byte[] bytes1, byte[] bytes2) {
        int diff;

        for (int i = 0; i < bytes1.length && i < bytes2.length; i++) {
            diff = (bytes1[i] & 0xFF) - (bytes2[i] & 0xFF);
            if (diff != 0) {
                return diff;
            }
        }

        
        // if array entries are equal till the first ends, then the longer is "bigger"
        return bytes1.length - bytes2.length;
    }
}
