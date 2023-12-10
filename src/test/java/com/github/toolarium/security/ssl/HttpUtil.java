/*
 * HttpUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.ssl;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * HTTPUtil class.
 * 
 * @author patrick
 */
public final class HttpUtil {
    // DateFormat to be used to format dates: RFC 1123 date string -- "Sun, 06 Nov 1994 08:49:37 GMT"
    private static final DateFormat RFC_1123_FORMAT = new SimpleDateFormat("EEE, dd MMM yyyyy HH:mm:ss z", Locale.US);
    private static final Logger LOG = LoggerFactory.getLogger(HttpUtil.class);
    private static final String NL = "\n";


    static {
        RFC_1123_FORMAT.setTimeZone(TimeZone.getTimeZone("GMT"));
    }

    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final HttpUtil INSTANCE = new HttpUtil();
    }

    
    /**
     * Constructor
     */
    private HttpUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static HttpUtil getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Get header lines
     *
     * @param reader the reader
     * @return the header lines
     * @throws IOException In case of an I/O error
     */
    public List<String> getHeaderLines(BufferedReader reader) throws IOException {
        final List<String> lines = new ArrayList<String>();
        
        // an empty line marks the end of the request's header
        String line = reader.readLine();
        while (!line.isEmpty()) {
            lines.add(line);
            line = reader.readLine();
        }
        return lines;
    }


    /**
     * Read request content
     * 
     * @param reader the reader
     * @param contentLength the content length
     * @return the read content
     * @throws IOException In case of an IO exception
     */
    public String readRequestContent(BufferedReader reader, int contentLength) throws IOException {
        StringBuilder content = new StringBuilder();
        LOG.debug("Request content length to read: " + contentLength);
        for (int i = 0; i < contentLength; i++) {
            content.append((char) reader.read());
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Read content: [" + content.toString() + "]");
        }
        
        return content.toString();
    }

    
    /**
     * Get the content length
     *
     * @param headerLines the header lines
     * @return the request content lentgh
     */
    public int getContentLength(List<String> headerLines) {
        for (String header : headerLines) {
            if (header.toLowerCase().startsWith("Content-Length".toLowerCase())) {
                String[] sl = header.split(":");
                if (sl.length > 1 && !sl[1].isBlank()) {
                    try {
                        return Integer.parseInt(sl[1].trim());
                    } catch (NumberFormatException e) {
                        // NOP
                    }
                }
            }
        }
        
        return 0;
    }

    
    /**
     * Write http response header
     *
     * @param writer the buffered writer
     * @param encoding the encoding
     * @param status the http status
     * @param contentType the content type
     * @param body the body
     * @throws IOException In case of IO error
     */
    public void write(BufferedWriter writer, Charset encoding, String status, String contentType, String body) throws IOException {
        final String dateStr = RFC_1123_FORMAT.format(new Date());

        byte[] bodyContent = null;
        int contentLength = 0;
        if (body != null && !body.isEmpty()) {
            bodyContent = body.getBytes(encoding);
            contentLength = bodyContent.length;
        }

        StringBuilder content = new StringBuilder();
        content.append("HTTP/1.1 ").append(status).append(NL)
        .append("Date: ").append(dateStr).append(NL)
        .append("Server: toolarium").append(NL)
        .append("Last-Modified: ").append(dateStr).append(NL)
        .append("Content-Length: ").append(contentLength).append(NL)
        .append("Content-Type: ").append(contentType).append("; charset=").append(encoding.displayName()).append(NL)
        .append("Connection: Closed").append(NL).append(NL);
        writer.write(content.toString());

        if (bodyContent != null) {
            writer.write(body);
        }
        
        writer.newLine();
    }
}
