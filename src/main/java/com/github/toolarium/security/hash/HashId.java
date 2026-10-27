/*
 * HashId.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.hash;

import com.github.toolarium.common.util.StringUtil;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;


/**
 * HashId: A small Java class to generate YouTube-like hashes from one or many numbers, ported from javascript hashids.js by Ivan Akimov.
 * It was designed for web sites to use in URL shortening, tracking stuff, or making pages private (or at least unguessable).
 * This algorithm tries to satisfy the following requirements: Hashes must be unique and decryptable.
 * They should be able to contain more than one integer (so you can use them in complex or clustered systems).
 * You should be able to specify minimum hash length.
 * Hashes should not contain basic English curse words (since they are meant to appear in public places, like the URL).
 * Instead of showing items as 1, 2, or 3, you could show them as U6dc, u87U, and HMou. You don't have to store these hashes 
 * in the database, but can encrypt + decrypt on the fly.
 * All (long) integers need to be greater than or equal to zero.
 * 
 * @author patrick
 */
public final class HashId {
    private static final String DEFAULT_ALPHABET = "xcS4F6h89aUbideAI7tkynuopqrXCgTE5GBKHLMjfRsz";

    private static final int[] PRIMES = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43 };
    private static final int[] SEPS_INDICES = {0, 4, 8, 12 };
    private final String salt;
    private final String alphabet;
    private final int minHashLength;
    private final List<Character> seps;
    private final List<Character> guards;


    /**
     * Constructor for HashId
     * 
     * @param salt the salt
     * @param minHashLength the min length
     * @param alphabet the alphabet
     * @throws IllegalArgumentException In case of an invalid input
     */
    private HashId(String salt, int minHashLength, String alphabet) {
        if (alphabet == null || alphabet.trim().isEmpty()) {
            throw new IllegalArgumentException("alphabet must not be empty");
        }
        
        if (salt != null) {
            this.salt = salt;
        } else {
            this.salt = "";
        }

        if (minHashLength > 0) {
            this.minHashLength = minHashLength;
        } else {
            this.minHashLength = 0;
        }

        //this.alphabet = join(new LinkedHashSet<String>(StringUtil.getInstance().splitAsList(alphabet, "")), "");
        List<String> list = StringUtil.getInstance().splitAsList(alphabet, "");
        list = list.stream().distinct().collect(Collectors.toList());
        String uniqueAlphabet = join(list, "");
        if (uniqueAlphabet.length() < 4) {
            throw new IllegalArgumentException("Alphabet must contain at least 4 unique characters.");
        }

        seps = new ArrayList<Character>();
        guards = new ArrayList<Character>();
        for (int prime : PRIMES) {
            if (prime < uniqueAlphabet.length()) {
                char c = uniqueAlphabet.charAt(prime - 1);
                seps.add(c);
                uniqueAlphabet = uniqueAlphabet.replace(c, ' ');
            }
        }

        for (int index : SEPS_INDICES) {
            if (index < seps.size()) {
                guards.add(seps.get(index));
                seps.remove(index);
            }
        }

        this.alphabet = consistentShuffle(uniqueAlphabet.replaceAll(" ", ""), this.salt);
    }
    
    
    /**
     * Create a hash id class
     * 
     * @return the instance
     */
    public static HashId createHashId() {
        return new HashId("", 0, DEFAULT_ALPHABET);
    }

    
    /**
     * Create a hash id class
     * 
     * @param salt the salt
     * @return the instance
     */
    public static HashId createHashId(String salt) {
        return new HashId(salt, 0, DEFAULT_ALPHABET);
    }
    
    
    /**
     * Create a hash id class
     * 
     * @param salt the salt
     * @param minHashLength the min hash length
     * @return the instance
     */
    public static HashId createHashId(String salt, int minHashLength) {
        return new HashId(salt, minHashLength, DEFAULT_ALPHABET);
    }

    
    /**
     * Create a hash id class
     * 
     * @param salt the salt
     * @param minHashLength the min hash length
     * @param alphabet the alphabet
     * @return the instance
     */
    public static HashId createHashId(String salt, int minHashLength, String alphabet) {
        return new HashId(salt, minHashLength, alphabet);
    }

    
    /**
     * Get the salt
     * 
     * @return the salt
     */
    public String getSalt() {
        return salt;
    }

    
    /**
     * Get the alphabet
     * 
     * @return the alphabet
     */
    public String getAlphabet() {
        return alphabet;
    }

    
    /**
     * Get the min hash length
     * 
     * @return the min hash length
     */
    public int getMinHashLength() {
        return minHashLength;
    }

    
    /**
     * Encrypt (obfuscate) the given numbers into a hash id. This is a reversible obfuscation, not an encryption:
     * it must not be used to protect confidential data.
     *
     * <p>The sign is not encoded: a negative number is encoded as its absolute value.</p>
     *
     * @param inputNumbers some numbers
     * @return the generated hash id
     * @throws IllegalArgumentException if the numbers are null or contain {@link Long#MIN_VALUE}, which has no absolute value
     */
    public String encrypt(long... inputNumbers) {
        if (inputNumbers == null) {
            throw new IllegalArgumentException("Invalid numbers (null)!");
        }

        long[] numbers = new long[inputNumbers.length];
        for (int i = 0; i < numbers.length; i++) {
            if (inputNumbers[i] == Long.MIN_VALUE) {
                throw new IllegalArgumentException("Long.MIN_VALUE can not be encoded!");
            }

            if (inputNumbers[i] < 0) {
                numbers[i] = -1 * inputNumbers[i];
            } else {
                numbers[i] = inputNumbers[i];
            }
        }

        return encode(numbers, alphabet, salt, minHashLength);
    }

    
    /**
     * Decrypt
     * 
     * @param hash the hash to decrypt
     * @return the decrypted hash or an empty array if the hash is invalid
     */
    public long[] decrypt(String hash) {
        long[] inputNumbers;
        try {
            inputNumbers = decode(hash);
        } catch (RuntimeException e) {
            // malformed input (e.g. only guard characters): treat as invalid hash
            return new long[0];
        }

        long[] numbers = new long[inputNumbers.length];

        for (int i = 0; i < inputNumbers.length; i++) {
            if (inputNumbers[i] < 0) {
                numbers[i] = -1 * inputNumbers[i];
            } else {
                numbers[i] = inputNumbers[i];
            }
        }

        return numbers;
    }

    
    /**
     * Encode
     * 
     * @param numbers the numbers
     * @param inputAlphabet the alphabet
     * @param inputSalt the salt
     * @param inputMinHashLength the min length
     * @return the hash
     */
    private String encode(long[] numbers, String inputAlphabet, String inputSalt, int inputMinHashLength) {
        String alphabet = inputAlphabet;
        StringBuilder ret = new StringBuilder();
        String shuffeltSeps = consistentShuffle(join(seps, ""), join(numbers, ""));
        char lotteryChar = 0;

        for (int i = 0; i < numbers.length; i++) {
            if (i == 0) {
                StringBuilder lotterySaltBuilder = new StringBuilder(join(numbers, "-"));
                for (long number : numbers) {
                    lotterySaltBuilder.append("-").append((number + 1) * 2);
                }
                String lotterySalt = lotterySaltBuilder.toString();

                String lottery = consistentShuffle(alphabet, lotterySalt);
                lotteryChar = lottery.charAt(0);
                ret.append(lotteryChar);

                alphabet = lotteryChar + alphabet.replace(String.valueOf(lotteryChar), "");
            }

            alphabet = consistentShuffle(alphabet, (lotteryChar & 12345) + inputSalt);
            ret.append(hash(numbers[i], alphabet));

            if (i + 1 < numbers.length) {
                // floorMod: numbers[i] + i can overflow for numbers close to Long.MAX_VALUE
                ret.append(shuffeltSeps.charAt((int) Math.floorMod(numbers[i] + i, (long) shuffeltSeps.length())));
            }
        }

        if (ret.length() < inputMinHashLength) {
            // the sum is truncated to int (as before) to keep the generated ids stable; floorMod ensures that an
            // overflowed (negative) sum still selects a guard, otherwise the padded id could not be decoded anymore
            int firstIndex = 0;
            for (int i = 0; i < numbers.length; i++) {
                firstIndex += (i + 1) * numbers[i];
            }

            int guardIndex = Math.floorMod(firstIndex, guards.size());
            if (guardIndex >= 0) {
                char guard = guards.get(guardIndex);
                ret.insert(0, guard);

                if (ret.length() < inputMinHashLength) {
                    guardIndex = (guardIndex + ret.length()) % guards.size();
                    guard = guards.get(guardIndex);
                    ret.append(guard);
                }
            }
        }

        int maxPaddingIterations = inputMinHashLength + 10;
        while (ret.length() < inputMinHashLength && maxPaddingIterations-- > 0) {
            long[] padArray = new long[] {alphabet.charAt(1), alphabet.charAt(0) };
            String padLeft = encode(padArray, alphabet, inputSalt, 0);
            String padRight = encode(padArray, alphabet, join(padArray, ""), 0);

            ret = new StringBuilder(padLeft).append(ret).append(padRight);
            int excess = ret.length() - inputMinHashLength;
            if (excess > 0) {
                ret = new StringBuilder(ret.substring(excess / 2, excess / 2 + inputMinHashLength));
            }

            alphabet = consistentShuffle(alphabet, inputSalt + ret.toString());
        }

        return ret.toString();
    }
    
    
    /**
     * Decode
     * 
     * @param inputHash the input hash
     * @return the id's
     */
    private long[] decode(String inputHash) {
        String hash = inputHash;
        List<Long> ret = new ArrayList<Long>();
        String originalHash = hash;

        if (hash != null && !hash.isEmpty()) {

            for (char guard : guards) {
                hash = hash.replace(guard, ' ');
            }
            
            String[] hashSplit = StringUtil.getInstance().splitAsArray(hash, " ");
            if (hashSplit.length == 3 || hashSplit.length == 2) {
                hash = hashSplit[1];
            } else {
                hash = hashSplit[0];
            }

            for (char sep : seps) {
                hash = hash.replace(sep, ' ');
            }
            
            String a = "";
            char lotteryChar = 0;
            String[] hashArray = StringUtil.getInstance().splitAsArray(hash, " ");
            for (int i = 0; i < hashArray.length; i++) {
                String subHash = hashArray[i];

                if (subHash != null && !subHash.isEmpty()) {
                    if (i == 0) {
                        lotteryChar = hash.charAt(0);
                        subHash = subHash.substring(1);
                        a = lotteryChar + alphabet.replace(String.valueOf(lotteryChar), "");
                    }
                }

                if (a.length() > 0) {
                    a = consistentShuffle(a, (lotteryChar & 12345) + salt);
                    ret.add(unhash(subHash, a));
                }
            }
        }

        long[] numbers = longListToPrimitiveArray(ret);
        if (!encrypt(numbers).equals(originalHash)) {
            return new long[0];
        }
        
        return numbers;
    }
    
    
    /**
     * Hash
     * 
     * @param inputNumber the input number
     * @param inputAlphabet the alphabet
     * @return the hash
     */
    private String hash(long inputNumber, String inputAlphabet) {
        long number = inputNumber;
        String hash = "";

        do {
            hash = inputAlphabet.charAt((int) (number % inputAlphabet.length())) + hash;
            number = number / inputAlphabet.length();
        } while (number > 0);

        return hash;
    }

    
    /**
     * Unhash
     * 
     * @param hash the hash
     * @param inputAlphabet the alphabet
     * @return the result
     */
    private long unhash(String hash, String inputAlphabet) {
        long number = 0;

        for (int i = 0; i < hash.length(); i++) {
            int pos = inputAlphabet.indexOf(hash.charAt(i));
            // exact integer arithmetic (Horner scheme): Math.pow loses precision for numbers > 2^53
            number = number * inputAlphabet.length() + pos;
        }

        return number;
    }

    
    /**
     * Consistent shuffle
     * 
     * @param alphabet the alphabet 
     * @param inputSalt the input salt
     * @return the result
     */
    private static String consistentShuffle(String alphabet, String inputSalt) {
        String ret = "";
        String salt = inputSalt;

        if (!alphabet.isEmpty()) {
            if (salt == null || salt.isEmpty()) {
                salt = new String(new char[] {'\0' });
            }
            
            int[] sortingArray = new int[salt.length()];
            for (int i = 0; i < salt.length(); i++) {
                sortingArray[i] = salt.charAt(i);
            }

            for (int i = 0; i < sortingArray.length; i++) {
                boolean add = true;
                for (int k = i; k != sortingArray.length + i - 1; k++) {
                    int nextIndex = (k + 1) % sortingArray.length;

                    if (add) {
                        sortingArray[i] += sortingArray[nextIndex] + (k * i);
                    } else {
                        sortingArray[i] -= sortingArray[nextIndex];
                    }

                    add = !add;
                }

                sortingArray[i] = Math.abs(sortingArray[i]);
            }

            // Use char[] + System.arraycopy to preserve the same removal-by-shift order as the
            // original ArrayList.remove(int), while avoiding O(n) object allocation per step.
            // StringBuilder replaces O(n²) string concatenation with O(n) amortised appends.
            char[] remaining = alphabet.toCharArray();
            int len = remaining.length;
            StringBuilder sb = new StringBuilder(len);
            int i = 0;
            while (len > 0) {
                int pos = sortingArray[i] % len;
                sb.append(remaining[pos]);
                System.arraycopy(remaining, pos + 1, remaining, pos, len - pos - 1);
                len--;
                i = (i + 1) % sortingArray.length;
            }
            ret = sb.toString();
        }

        return ret;
    }
 
    
    /**
     * Convert long list into a primitive array 
     * 
     * @param longList the long list
     * @return the primitive array
     */
    private static long[] longListToPrimitiveArray(List<Long> longList) {
        long[] longArr = new long[longList.size()];
        int i = 0;

        for (long l : longList) {
            longArr[i++] = l;
        }

        return longArr;
    }

    
    /**
     * Join long array with delimiter
     * 
     * @param longList the long value array
     * @param delimiter the delimiter
     * @return the string
     */
    private static String join(long[] longList, String delimiter) {
        ArrayList<String> strList = new ArrayList<String>(longList.length);
        for (long l : longList) {
            strList.add(String.valueOf(l));
        }

        return join(strList, delimiter);
    }

    
    /**
     * Join collection with delimiter
     * 
     * @param c the collection
     * @param delimiter the delimiter
     * @return the string
     */
    private static String join(Collection<?> c, String delimiter) {
        Iterator<?> iter = c.iterator();
        if (iter.hasNext()) {
            StringBuilder builder = new StringBuilder(c.size());
            builder.append(iter.next());
            while (iter.hasNext()) {
                builder.append(delimiter);
                builder.append(iter.next());
            }

            return builder.toString();
        }

        return "";
    }
}
