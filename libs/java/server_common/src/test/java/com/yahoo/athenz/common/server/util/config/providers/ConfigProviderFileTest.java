/*
 * Copyright The Athenz Authors.
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
package com.yahoo.athenz.common.server.util.config.providers;

import com.yahoo.athenz.common.server.util.config.ConfigEntry;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;

import static org.testng.Assert.*;

public class ConfigProviderFileTest {
    @Test
    public void testConfigProviderFile() throws IOException {

        File configFile = File.createTempFile("ConfigProviderFileTest", ".conf");
        try (PrintWriter out = new PrintWriter(configFile)) {
            out.print("  ConfigProviderFileTest-1 : value-1 \n" +
                    "  # remark \n" +
                    "  ConfigProviderFileTest-2 : value-2 \n");
        }

        ConfigProviderFile provider = new ConfigProviderFile();

        assertNull(provider.tryToBuildConfigSource("non-existing-file"));

        ConfigProviderFile.ConfigSourceFile nonExistingFileSource = provider.tryToBuildConfigSource("prop-file://non-existing-file");
        assertNotNull(nonExistingFileSource);
        assertThrows(IOException.class, nonExistingFileSource::getConfigEntries);

        ConfigProviderFile.ConfigSourceFile source = provider.tryToBuildConfigSource("prop-file://" + configFile.getAbsolutePath());
        assertNotNull(source);
        assertEquals(configFile.getAbsolutePath(), source.file.getAbsolutePath());

        Collection<ConfigEntry> entries = source.getConfigEntries();
        assertEquals(2, entries.size());

        ConfigEntry first = entries.stream().filter(entry -> entry.key.equals("ConfigProviderFileTest-1")).findFirst().orElse(null);
        assertNotNull(first);
        assertEquals("value-1", first.value);
        assertEquals(source, first.sourceSource);

        ConfigEntry second = entries.stream().filter(entry -> entry.key.equals("ConfigProviderFileTest-2")).findFirst().orElse(null);
        assertNotNull(second);
        assertEquals("value-2", second.value);
        assertEquals(source, second.sourceSource);

        @SuppressWarnings("unused") boolean deleted = configFile.delete();
    }
}