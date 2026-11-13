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
package com.yahoo.athenz.zts.bundle;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/**
 * Minimal independent tar reader used to verify the archives generated
 * by the main code (ustar headers and PAX path records).
 */
public class TarTestUtils {

    public static byte[] gunzip(byte[] archive) throws IOException {
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(archive))) {
            return in.readAllBytes();
        }
    }

    public static Map<String, byte[]> readTar(byte[] tar) {
        return readTar(tar, new LinkedHashMap<>());
    }

    /**
     * Parse the tar and return path to content. The mtime of each entry is
     * stored in the mtimes map (keyed by path) when it's provided.
     */
    public static Map<String, byte[]> readTar(byte[] tar, Map<String, Long> times) {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        int pos = 0;
        String paxPath = null;
        while (pos + 512 <= tar.length) {
            if (isZeroBlock(tar, pos)) {
                break;
            }
            verifyChecksum(tar, pos);
            String name = cString(tar, pos, 100);
            long size = Long.parseLong(cString(tar, pos + 124, 12).trim(), 8);
            long mtime = Long.parseLong(cString(tar, pos + 136, 12).trim(), 8);
            char type = (char) tar[pos + 156];
            if (!"ustar".equals(cString(tar, pos + 257, 6))) {
                throw new IllegalStateException("missing ustar magic");
            }
            pos += 512;
            byte[] data = new byte[(int) size];
            System.arraycopy(tar, pos, data, 0, (int) size);
            pos += (int) (((size + 511) / 512) * 512);
            if (type == 'x') {
                paxPath = parsePaxPath(data);
            } else if (type == '0') {
                if (paxPath != null) {
                    name = paxPath;
                    paxPath = null;
                }
                if (entries.put(name, data) != null) {
                    throw new IllegalStateException("duplicate entry: " + name);
                }
                times.put(name, mtime);
            } else {
                throw new IllegalStateException("unexpected type: " + type);
            }
        }
        // the archive must end with two zero blocks
        if (!isZeroBlock(tar, pos) || !isZeroBlock(tar, pos + 512) || tar.length != pos + 1024) {
            throw new IllegalStateException("invalid archive trailer");
        }
        return entries;
    }

    static String parsePaxPath(byte[] data) {
        String path = null;
        int pos = 0;
        while (pos < data.length) {
            int space = pos;
            while (data[space] != ' ') {
                space++;
            }
            int length = Integer.parseInt(new String(data, pos, space - pos, StandardCharsets.US_ASCII));
            if (data[pos + length - 1] != '\n') {
                throw new IllegalStateException("pax record length mismatch");
            }
            String record = new String(data, space + 1, pos + length - 1 - (space + 1), StandardCharsets.UTF_8);
            if (record.startsWith("path=")) {
                path = record.substring(5);
            }
            pos += length;
        }
        return path;
    }

    static void verifyChecksum(byte[] tar, int pos) {
        long expected = Long.parseLong(cString(tar, pos + 148, 8).trim(), 8);
        long sum = 0;
        for (int i = 0; i < 512; i++) {
            sum += (i >= 148 && i < 156) ? ' ' : (tar[pos + i] & 0xFF);
        }
        if (sum != expected) {
            throw new IllegalStateException("checksum mismatch");
        }
    }

    static boolean isZeroBlock(byte[] tar, int pos) {
        if (pos + 512 > tar.length) {
            return false;
        }
        for (int i = 0; i < 512; i++) {
            if (tar[pos + i] != 0) {
                return false;
            }
        }
        return true;
    }

    static String cString(byte[] data, int offset, int length) {
        int end = offset;
        while (end < offset + length && data[end] != 0) {
            end++;
        }
        return new String(data, offset, end - offset, StandardCharsets.UTF_8);
    }
}
