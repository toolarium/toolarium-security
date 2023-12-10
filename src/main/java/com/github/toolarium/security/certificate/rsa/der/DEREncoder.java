/*
 * DEREncoder.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.rsa.der;

import java.io.IOException;
import java.io.OutputStream;


/**
 * Interface to an object that knows how to write its own DER encoding to an output stream.
 * 
 * @author patrick
 */
public interface DEREncoder {
    
    /**
     * DER encode this object and write the results to a stream.
     *
     * @param out  the stream on which the DER encoding is written.
     * @throws IOException in case of error
     */
    void derEncode(OutputStream out) throws IOException;
}
