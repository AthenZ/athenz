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

import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.*;

public class TarArchiveWriterTest {

    @Test
    public void testEmptyArchive() {
        byte[] tar = new TarArchiveWriter(0).finish();
        assertEquals(tar.length, 1024);
        assertTrue(readTar(tar).isEmpty());
    }

    private Map<String, byte[]> readTar(byte[] tar) {
        return TarTestUtils.readTar(tar);
    }

    @Test
    public void testShortNamesAndPadding() {
        TarArchiveWriter writer = new TarArchiveWriter(1700000000L);
        byte[] big = new byte[1024];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) i;
        }
        writer.addFile("a.txt", "hello".getBytes(StandardCharsets.UTF_8));
        writer.addFile("dir/empty", new byte[0]);
        writer.addFile("dir/exact512", new byte[512]);
        writer.addFile("dir/big", big);
        byte[] tar = writer.finish();

        // 3 file headers + data blocks: 1 + 0 + 1 + 2 and the empty file header
        assertEquals(tar.length % 512, 0);

        Map<String, Long> mtimes = new HashMap<>();
        Map<String, byte[]> entries = TarTestUtils.readTar(tar, mtimes);
        assertEquals(entries.size(), 4);
        assertEquals(new String(entries.get("a.txt"), StandardCharsets.UTF_8), "hello");
        assertEquals(entries.get("dir/empty").length, 0);
        assertEquals(entries.get("dir/exact512").length, 512);
        assertEquals(entries.get("dir/big"), big);
        assertEquals(mtimes.get("a.txt").longValue(), 1700000000L);

        // header sanity: name at offset 0, mode 0644, ustar magic
        assertEquals(new String(tar, 0, 5, StandardCharsets.US_ASCII), "a.txt");
        assertEquals(new String(tar, 100, 7, StandardCharsets.US_ASCII), "0000644");
        assertEquals(new String(tar, 257, 5, StandardCharsets.US_ASCII), "ustar");
    }

    @Test
    public void testNameExactlyHundredBytesHasNoPaxHeader() {
        String name = "a".repeat(100);
        TarArchiveWriter writer = new TarArchiveWriter(0);
        writer.addFile(name, "x".getBytes(StandardCharsets.UTF_8));
        byte[] tar = writer.finish();
        // header + data + trailer
        assertEquals(tar.length, 512 + 512 + 1024);
        assertEquals(tar[156], (byte) '0');
        assertNotNull(readTar(tar).get(name));
    }

    @Test
    public void testLongNameUsesPaxHeader() {
        String name = "very/long/".repeat(20) + "file.rego";
        assertTrue(name.length() > 100);
        TarArchiveWriter writer = new TarArchiveWriter(5);
        writer.addFile(name, "package x".getBytes(StandardCharsets.UTF_8));
        writer.addFile("short", "s".getBytes(StandardCharsets.UTF_8));
        byte[] tar = writer.finish();

        // first header is the pax extended header
        assertEquals(tar[156], (byte) 'x');

        Map<String, byte[]> entries = readTar(tar);
        assertEquals(entries.size(), 2);
        assertEquals(new String(entries.get(name), StandardCharsets.UTF_8), "package x");
        assertEquals(new String(entries.get("short"), StandardCharsets.UTF_8), "s");
    }

    @Test
    public void testLongMultiByteNameUsesPaxHeader() {
        // 40 chars x 3 bytes = 120 bytes in utf-8 while only 40 characters
        String name = "€".repeat(40);
        TarArchiveWriter writer = new TarArchiveWriter(0);
        writer.addFile(name, "x".getBytes(StandardCharsets.UTF_8));
        Map<String, byte[]> entries = readTar(writer.finish());
        assertNotNull(entries.get(name));
    }

    @Test
    public void testPaxRecordLength() {
        // length includes its own digits: short, and across digit boundaries
        for (int valueLength : new int[] { 101, 120, 985, 990, 991, 995, 1100 }) {
            String value = "p".repeat(valueLength);
            byte[] record = TarArchiveWriter.paxRecord("path", value);
            String text = new String(record, StandardCharsets.UTF_8);
            int space = text.indexOf(' ');
            assertEquals(Integer.parseInt(text.substring(0, space)), record.length, "value length " + valueLength);
            assertTrue(text.endsWith("path=" + value + "\n"));
        }
    }

    @Test
    public void testVeryLongName() {
        String name = "d/".repeat(600) + "f";
        TarArchiveWriter writer = new TarArchiveWriter(0);
        writer.addFile(name, "x".getBytes(StandardCharsets.UTF_8));
        assertNotNull(readTar(writer.finish()).get(name));
    }

    @Test
    public void testWriteOctal() {
        byte[] header = new byte[32];
        TarArchiveWriter.writeOctal(header, 4, 12, 8);
        assertEquals(new String(header, 4, 11, StandardCharsets.US_ASCII), "00000000010");
        assertEquals(header[15], 0);
        assertEquals(header[3], 0);
    }

    @Test
    public void testShortName() {
        byte[] name = ("x".repeat(10) + "y".repeat(100)).getBytes(StandardCharsets.UTF_8);
        byte[] result = TarArchiveWriter.shortName(name);
        assertEquals(result.length, 100);
        assertEquals(new String(result, StandardCharsets.UTF_8), "y".repeat(100));
    }
}
