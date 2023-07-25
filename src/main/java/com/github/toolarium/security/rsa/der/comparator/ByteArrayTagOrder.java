/*
 * ByteArrayTagOrder.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.rsa.der.comparator;

import java.util.Comparator;


/**
 * ByteArrayTagOrder: a class for comparing two DER encodings by the order of their tags.
 * 
 * @author patrick
 */
public class ByteArrayTagOrder implements Comparator<byte[]> {
    
    /**
     * Compare two byte arrays, by the order of their tags, as defined in ITU-T X.680, sec. 6.4.  (First compare
     * tag classes, then tag numbers, ignoring the constructivity bit.)
     *
     * @param  bytes1 first byte array to compare.
     * @param  bytes2 second byte array to compare.
     * @return negative number if obj1 &lt; obj2, 0 if obj1 == obj2, positive number if obj1 &gt; obj2.  
     */
    @Override
    public final int compare(byte[] bytes1, byte[] bytes2) {
        // tag order is same as byte order ignoring any difference in the constructivity bit (0x02)
        return (bytes1[0] | 0x20) - (bytes2[0] | 0x20);
    }   
}
