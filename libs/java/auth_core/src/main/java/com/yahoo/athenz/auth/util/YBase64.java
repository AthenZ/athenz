/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.auth.util;

import java.util.Arrays;

/**
 * Y64 Encode/Decode support:
 * URL friendly base64 encoding, it replaces + and / with . and _ and uses - for padding.
 * Original implementation is from Java Platforms
 */

public class YBase64 {

    private static final byte[] Y64_ARRAY = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
            '4', '5', '6', '7', '8', '9', '.', '_'
    };

    public static final byte[] Y64_DECODE_ARRAY = {
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xff, 62, (byte) 0xee, 52,
            53, 54, 55, 56, 57, 58, 59, 60, 61, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, 63,
            (byte) 0xee, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee,
            (byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee
    };

    private static byte decodeByte(int index) {
        // java has signed bytes, and the good values are up to 122, so any
        // negative indexes are signed byte conversions of >128 and invalid
        if (index < 0 || index >= Y64_DECODE_ARRAY.length) {
            return (byte) 0xee;
        }
        return Y64_DECODE_ARRAY[index];
    }

    private static byte encode1(byte ba) {
        // enc1: Y64_array[(a >> 2)];
        // have to make value into an int so we can do shifts.
        // but we need to mask off the sign bit.
        final int a = ((int) ba) & 0x00ff;
        final int i = (a >> 2);
        if (i < 0 || i >= Y64_DECODE_ARRAY.length) {
            return (byte) 0xee;
        }
        return Y64_ARRAY[i];
    }

    private static byte encode2(byte ba, byte bb) {
        // enc2: Y64_array[((a << 4) & 0x30) + (b >> 4)];
        // have to make value into an int so we can do shifts.
        // but we need to mask off the sign bit.
        final int a = ((int) ba) & 0x00ff;
        final int b = ((int) bb) & 0x00ff;
        final int i = ((a << 4) & 0x30) + (b >> 4);
        if (i < 0 || i >= Y64_DECODE_ARRAY.length) {
            return (byte) 0xee;
        }
        return Y64_ARRAY[i];
    }

    private static byte encode3(byte bb, byte bc) {
        // enc3: Y64_array[((b << 2) & 0x3C) + (c >> 6)];
        // have to make value into an int so we can do shifts.
        // but we need to mask off the sign bit.
        final int b = ((int) bb) & 0x00ff;
        final int c = ((int) bc) & 0x00ff;
        final int i = ((b << 2) & 0x3C) + (c >> 6);
        if (i < 0 || i >= Y64_DECODE_ARRAY.length) {
            return (byte) 0xee;
        }
        return Y64_ARRAY[i];
    }

    private static byte encode4(byte bc) {
        // enc4: Y64_array[c & 0x3F];
        // have to make value into an int so we can do shifts.
        // but we need to mask off the sign bit.
        final int i = ((int) bc) & 0x003f;
        if (i < 0 || i >= Y64_DECODE_ARRAY.length) {
            return (byte) 0xee;
        }
        return Y64_ARRAY[i];
    }

    private static byte decode1(byte a, byte b) {
        return (byte) ((a << 2) + (b >> 4));
    }

    private static byte decode2(byte b, byte c) {
        return (byte) ((b << 4) + (c >> 2));
    }

    private static byte decode3(byte c, byte d) {
        return (byte) ((c << 6) + d);
    }

    /**
     * Decode the given byte array and return the result
     * @param inBytes byte array to be decoded
     * @return decoded byte array
     * @throws CryptoException in case of invalid padding or characters
     */
    public static byte[] decode(byte[] inBytes) {

        if (null == inBytes) {
            throw new NullPointerException("Null input buffer");
        }

        /* Sanity check, should always be padded at the end. */
        int len = inBytes.length;
        if (len % 4 != 0 && inBytes[len - 1] == '\0') {
            len -= 1;
        }

        if (len % 4 != 0) {
            throw new CryptoException("String not padded ie, input string not modulo 4 len =  " + len
                            + " len%4= " + len % 4);
        }

        byte[] out = new byte[y64decodeLen(len)];

        int i = 0;
        int j = 0;
        int tlen;
        while (i < len) {
            tlen = (len - i);
            if (tlen > 4) {
                tlen = 4;
            }

            /* Figure out how long "tlen" really is */
            if (inBytes[i + 3] == '-') {
                tlen--;
            }
            if (inBytes[i + 2] == '-') {
                tlen--;
            }

            if (inBytes[i + 1] == '-') { /* This case should NEVER happen. */
                throw new CryptoException("Too Many pad characters ( this should never happen )");
            }

            /* decode */
            byte a = decodeByte(inBytes[i++]);
            byte b = decodeByte(inBytes[i++]);
            byte c = decodeByte(inBytes[i++]);
            byte d = decodeByte(inBytes[i++]);

            /* validate */
            if (a == (byte) 0xee || b == (byte) 0xee || c == (byte) 0xee || d == (byte) 0xee) {
                throw new CryptoException("Unrecognized characters in y64-encoded input starting at: " + (i - 4));
            }

            if (tlen == 4) {
                // dec1: ((a << 2) + (b >> 4));
                out[j++] = decode1(a, b);
                // dec2: ((b << 4) + (c >> 2));
                out[j++] = decode2(b, c);
                // dec3: ((c << 6) + d);
                out[j++] = decode3(c, d);
            } else if (tlen == 3) {
                if ((c & (byte) 0x03) != 0) {
                    throw new CryptoException("Unknown decode error c & 0x03 failed, c-pos: " + (i - 2));
                }
                // dec1: ((a << 2) + (b >> 4));
                out[j++] = decode1(a, b);
                // dec2: ((b << 4) + (c >> 2));
                out[j++] = decode2(b, c);
            } else { /* tlen == 2 */
                if ((b & (byte) 0x0F) != 0) {
                    throw new CryptoException("Invalid decode. b & 0x0f failed, b-pos: " + (i - 3));
                }
                // dec1: ((a << 2) + (b >> 4));
                out[j++] = decode1(a, b);
            }
        }
        
        return Arrays.copyOf(out, j);
    }

    /**
     * Encode given byte array into Y64 format.
     * @param inBytes data to be encoded
     * @return encoded Y64 byte array
     * @throws NullPointerException if the input buffer is null
     */
    public static byte[] encode(byte[] inBytes) {
        
        if (null == inBytes) {
            throw new NullPointerException("input buffer was null");
        }

        /* Sanity check, should always be padded at the end. */
        if (inBytes.length < 1) {
            return new byte[] {};
        }

        int len = inBytes.length;
        int encodeLen = y64encodeLen(len);
        byte[] out = new byte[encodeLen];
        int j = 0;
        int tlen;

        for (int i = 0; i < len; i += 3) {

            tlen = (len - i);
            if (tlen > 3) {
                tlen = 3;
            }

            byte a;
            byte b;
            byte c;

            if (tlen == 1) {
                a = inBytes[i];
                b = 0;
                // enc1: Y64_array[(a >> 2)];
                out[j++] = encode1(a);
                // enc2: Y64_array[((a << 4) & 0x30) + (b >> 4)];
                out[j++] = encode2(a, b);
                out[j++] = '-';
                out[j++] = '-';
            } else if (tlen == 2) {
                a = inBytes[i];
                b = inBytes[i + 1];
                c = 0;
                // enc1: Y64_array[(a >> 2)];
                out[j++] = encode1(a);
                // enc2: Y64_array[((a << 4) & 0x30) + (b >> 4)];
                out[j++] = encode2(a, b);
                // enc3: Y64_array[((b << 2) & 0x3C) + (c >> 6)];
                out[j++] = encode3(b, c);
                out[j++] = '-';
            } else {
                a = inBytes[i];
                b = inBytes[i + 1];
                c = inBytes[i + 2];
                // enc1: Y64_array[(a >> 2)];
                out[j++] = encode1(a);
                // enc2: Y64_array[((a << 4) & 0x30) + (b >> 4)];
                out[j++] = encode2(a, b);
                // enc3: Y64_array[((b << 2) & 0x3C) + (c >> 6)];
                out[j++] = encode3(b, c);
                // enc4: Y64_array[c & 0x3F];
                out[j++] = encode4(c);
            }
        }

        return Arrays.copyOf(out, j);
    }
    
    static int y64decodeLen(int len) {
        // this is not -1 because strings have no null terminator.
        return (((len + 3) / 4) * 3) + 1;
    }

    static int y64encodeLen(int len) {
        // Could check for response length overflow - generated response 
        // is greater than max size_t can represent.
        return ((len + 2) / 3 * 4) + 1;
    }
}

