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

import static org.testng.Assert.*;

import java.nio.charset.StandardCharsets;

import org.testng.annotations.Test;

public class YBase64Test {

    final static String DOUBLE_PADDING = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRW"
            + "UlLb1pJemowREFRY0RRZ0FFeSszVEJJL281SzVwUFpQS2RYdk5YSmQ2L1hYYwpoMmNUQTgyRlVlcUVFU2QxUy9nTj"
            + "IrY0daRnhZOWNJYlRCL01vbDFueU9uOHFGQmpkS1JnSUM5MDlnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg--";
    final static String NO_PADDING = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRW"
            + "UlLb1pJemowREFRY0RRZ0FFa2Y5UzN3Q09tQ1BvbklQWTdGZHNHU05WQlAxOQorSlBMV2dST2hOV0pOMW1qZnNLa"
            + "GJvZXZjNHNxeGdlb2xQaERCLzExeVFWSVdpcFlGanlYdFJVT0pnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t";
    final static String SINGLE_PADDING = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRU"
            + "JCUUFEU3dBd1NBSkJBT0lRMlY1NURmQk93VjNBMTZ1andOcStKcCtMTURrNwpKUXZldThMT3J5R1pWc25aQmxFVit"
            + "za05FYTJzNzBHNmM4blBoRVJyZVBtYUQ2cjd5Wk50MGVVQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    
    final static String SINGLE_PAD_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
            + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOIQ2V55DfBOwV3A16ujwNq+Jp+LMDk7\n"
            + "JQveu8LOryGZVsnZBlEV+skNEa2s70G6c8nPhERrePmaD6r7yZNt0eUCAwEAAQ==\n"
            + "-----END PUBLIC KEY-----\n";
    final static String DOUBLE_PAD_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEy+3TBI/o5K5pPZPKdXvNXJd6/XXc\n"
            + "h2cTA82FUeqEESd1S/gN2+cGZFxY9cIbTB/Mol1nyOn8qFBjdKRgIC909g==\n"
            + "-----END PUBLIC KEY-----\n";
    final static String NO_PAD_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkf9S3wCOmCPonIPY7FdsGSNVBP19\n"
            + "+JPLWgROhNWJN1mjfsKhboevc4sqxgeolPhDB/11yQVIWipYFjyXtRUOJg==\n"
            + "-----END PUBLIC KEY-----";

    @Test
    public void testDecodeSinglePaddingCharacter() {
        byte[] data = YBase64.decode(SINGLE_PADDING.getBytes(StandardCharsets.UTF_8));
        assertEquals(new String(data, StandardCharsets.UTF_8), SINGLE_PAD_PUBLIC_KEY);
    }
    
    @Test
    public void testDecodeDoublePaddingCharacter() {
        byte[] data = YBase64.decode(DOUBLE_PADDING.getBytes(StandardCharsets.UTF_8));
        assertEquals(new String(data, StandardCharsets.UTF_8), DOUBLE_PAD_PUBLIC_KEY);
    }
    
    @Test
    public void testDecodeNoPaddingCharacter() {
        byte[] data = YBase64.decode(NO_PADDING.getBytes(StandardCharsets.UTF_8));
        assertEquals(new String(data, StandardCharsets.UTF_8), NO_PAD_PUBLIC_KEY);
    }
    
    @Test
    public void testEncodeSinglePaddingCharacter() {
        byte[] data = YBase64.encode(SINGLE_PAD_PUBLIC_KEY.getBytes(StandardCharsets.UTF_8));
        assertEquals(new String(data, StandardCharsets.UTF_8), SINGLE_PADDING);
    }
    
    @Test
    public void testEncodeDoublePaddingCharacter() {
        byte[] data = YBase64.encode(DOUBLE_PAD_PUBLIC_KEY.getBytes(StandardCharsets.UTF_8));
        assertEquals(new String(data, StandardCharsets.UTF_8), DOUBLE_PADDING);
    }
    
    @Test
    public void testEncodeNoPaddingCharacter() {
        byte[] data = YBase64.encode(NO_PAD_PUBLIC_KEY.getBytes(StandardCharsets.UTF_8));
        assertEquals(new String(data, StandardCharsets.UTF_8), NO_PADDING);
    }

    @Test
    public void testDecodeInvalidData() {
        try {
            YBase64.decode(null);
            fail();
        } catch (NullPointerException ignored) {
        }
        
        try {
            YBase64.decode("abcde\0".getBytes());
            fail();
        } catch (CryptoException ignored) {
        }
        
        try {
            YBase64.decode("a-aa".getBytes());
            fail();
        } catch (CryptoException ignored) {
        }
        
        try {
            byte[] a = new byte[] {(byte)0xff,(byte)0x97,(byte)0x97,(byte)0x97};
            YBase64.decode(a);
            fail();
        } catch (CryptoException ignored) {
        }
        
        try {
            byte[] b = new byte[] {(byte)0x97,(byte)0xff,(byte)0x97,(byte)0x97};
            YBase64.decode(b);
            fail();
        } catch (CryptoException ignored) {
        }
        
        try {
            byte[] c = new byte[] {(byte)0x97,(byte)0x97,(byte)0xff,(byte)0x97};
            YBase64.decode(c);
            fail();
        } catch (CryptoException ignored) {
        }
        
        try {
            byte[] d = new byte[] {(byte)0x97,(byte)0x97,(byte)0x97,(byte)0xff};
            YBase64.decode(d);
            fail();
        } catch (CryptoException ignored) {
        }
        
        try {
            YBase64.decode("aaa-".getBytes());
            fail();
        } catch (CryptoException ignored) {
        }
        
        try {
            YBase64.decode("aa--".getBytes());
            fail();
        } catch (CryptoException ignored) {
        }
    }
    
    @Test
    public void testEncodeInvalidData() {
        try {
            YBase64.encode(null);
            fail();
        } catch (NullPointerException ignored) {
        }
        
        byte[] data = new byte[0];
        assertNotNull(YBase64.encode(data));
    }

    @Test
    public void testRandom() {
        new YBase64();
    }
}
