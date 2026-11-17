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

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Minimal POSIX ustar archive writer for regular files only. Names longer
 * than 100 bytes are stored with a PAX extended header (path record), which
 * is supported by the Go archive/tar reader that OPA uses.
 */
public class TarArchiveWriter {

    static final int BLOCK_SIZE = 512;
    static final int NAME_LENGTH = 100;

    private static final byte TYPE_FILE = '0';
    private static final byte TYPE_PAX_HEADER = 'x';

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final long mtimeSeconds;

    public TarArchiveWriter(long mtimeSeconds) {
        this.mtimeSeconds = mtimeSeconds;
    }

    public void addFile(final String path, final byte[] content) {

        final byte[] name = path.getBytes(StandardCharsets.UTF_8);
        if (name.length > NAME_LENGTH) {
            final byte[] paxData = paxRecord("path", path);
            writeHeader(shortName(name), paxData.length, TYPE_PAX_HEADER);
            writeData(paxData);
            writeHeader(shortName(name), content.length, TYPE_FILE);
        } else {
            writeHeader(name, content.length, TYPE_FILE);
        }
        writeData(content);
    }

    public byte[] finish() {
        // end of archive is marked by two zero blocks
        out.writeBytes(new byte[BLOCK_SIZE * 2]);
        return out.toByteArray();
    }

    static byte[] shortName(final byte[] name) {
        byte[] result = new byte[NAME_LENGTH];
        System.arraycopy(name, name.length - NAME_LENGTH, result, 0, NAME_LENGTH);
        return result;
    }

    static byte[] paxRecord(final String key, final String value) {

        // each record is "<length> <key>=<value>\n" where length is the
        // decimal length of the full record including the length digits

        final int baseLength = 3 + key.getBytes(StandardCharsets.UTF_8).length
                + value.getBytes(StandardCharsets.UTF_8).length;
        int length = baseLength + Integer.toString(baseLength).length();
        if (Integer.toString(length).length() != Integer.toString(baseLength).length()) {
            length = baseLength + Integer.toString(length).length();
        }
        return (length + " " + key + "=" + value + "\n").getBytes(StandardCharsets.UTF_8);
    }

    void writeHeader(final byte[] name, long size, byte type) {

        byte[] header = new byte[BLOCK_SIZE];
        System.arraycopy(name, 0, header, 0, name.length);
        writeOctal(header, 100, 8, 0644);
        writeOctal(header, 108, 8, 0);
        writeOctal(header, 116, 8, 0);
        writeOctal(header, 124, 12, size);
        writeOctal(header, 136, 12, mtimeSeconds);
        header[156] = type;
        System.arraycopy("ustar\u000000".getBytes(StandardCharsets.US_ASCII), 0, header, 257, 8);

        // the checksum is computed with the checksum field set to spaces

        for (int i = 148; i < 156; i++) {
            header[i] = ' ';
        }
        long checksum = 0;
        for (byte b : header) {
            checksum += (b & 0xFF);
        }
        writeOctal(header, 148, 7, checksum);
        header[155] = ' ';
        out.writeBytes(header);
    }

    void writeData(final byte[] data) {
        out.writeBytes(data);
        final int remainder = data.length % BLOCK_SIZE;
        if (remainder != 0) {
            out.writeBytes(new byte[BLOCK_SIZE - remainder]);
        }
    }

    static void writeOctal(byte[] header, int offset, int length, long value) {

        // octal digits padded with leading zeros followed by a nul terminator

        final String octal = Long.toOctalString(value);
        final int digits = length - 1;
        StringBuilder field = new StringBuilder(digits);
        for (int i = octal.length(); i < digits; i++) {
            field.append('0');
        }
        field.append(octal);
        final byte[] bytes = field.toString().getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(bytes, 0, header, offset, digits);
        header[offset + digits] = 0;
    }
}
