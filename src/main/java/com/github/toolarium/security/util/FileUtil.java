/*
 * FileUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.util;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;


/**
 * File Util class
 * 
 * @author patrick
 */
public final class FileUtil {

    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final FileUtil INSTANCE = new FileUtil();
    }

    
    /**
     * Constructor
     */
    private FileUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static FileUtil getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Read the file content
     *
     * @param file the file
     * @return the content
     * @throws IOException In case of an IO error
     */
    public String readFileContent(File file) throws IOException {
        return readFileContent(file, StandardCharsets.UTF_8);
    }

    
    /**
     * Read the file content
     *
     * @param file the file
     * @return the content
     * @throws IOException In case of an IO error
     */
    public String readFileContent(Path file) throws IOException {
        return readFileContent(file, StandardCharsets.UTF_8);
    }

    
    /**
     * Read the file content
     *
     * @param file the file
     * @param charset the charset
     * @return the content
     * @throws IOException In case of an IO error
     */
    public String readFileContent(File file, Charset charset) throws IOException {
        if (file == null) {
            return null;
        }
        
        return readFileContent(file.toPath(), StandardCharsets.UTF_8);
    }

    
    /**
     * Read the file content
     *
     * @param file the file
     * @param charset the charset
     * @return the content
     * @throws IOException In case of an IO error
     */
    public String readFileContent(Path file, Charset charset) throws IOException {
        return new String(Files.readAllBytes(file), charset);
    }
}
