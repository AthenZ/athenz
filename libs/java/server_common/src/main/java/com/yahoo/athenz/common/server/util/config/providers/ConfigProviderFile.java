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

import com.yahoo.athenz.common.server.util.Utils;
import com.yahoo.athenz.common.server.util.config.ConfigEntry;

import jakarta.annotation.Nullable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

/**
 * A provider for config-files. <br>
 * The provider-description is "prop-file://...file-path..." <br>
 * The file syntax is specified here: {@link Properties#load(java.io.Reader)}. <br>
 * Generally, lines in a config-file looks like this: <pre>
 *     # remark
 *     key: value
 * </pre>
 */
public class ConfigProviderFile extends ConfigProvider {

    public static final String PROVIDER_DESCRIPTION_PREFIX = "prop-file://";

    @Override
    public @Nullable ConfigSourceFile tryToBuildConfigSource(String sourceDescription) {
        // Check if the provider-description matches "prop-file://...file-path..."
        if (!sourceDescription.startsWith(PROVIDER_DESCRIPTION_PREFIX)) {
            return null;
        }
        return new ConfigSourceFile(sourceDescription, new File(sourceDescription.substring(PROVIDER_DESCRIPTION_PREFIX.length())));
    }

    public static class ConfigSourceFile extends ConfigSource {

        public final File file;

        public ConfigSourceFile(String sourceDescription, File file) {
            super(sourceDescription);
            this.file = file;
        }

        /** Get all configuration entries of the source */
        @Override
        public Collection<ConfigEntry> getConfigEntries() throws IOException {
            // Parse the properties file.
            Properties properties;
            try {
                properties = new Properties();
                try (InputStream inputStream = new FileInputStream(file)) {
                    properties.load(inputStream);
                }
            } catch (IOException exception) {
                throw new IOException("Can't load config-file " + file.getAbsolutePath(), exception);
            }

            // Spill onto system-properties.
            List<ConfigEntry> configEntries = new LinkedList<>();
            Enumeration<?> enumeration = properties.propertyNames();
            while (enumeration.hasMoreElements()) {
                String propertyName = (String) enumeration.nextElement();
                String propertyValue = properties.getProperty(propertyName).trim();
                configEntries.add(new ConfigEntry(
                        propertyName,
                        propertyValue,
                        this,
                        null));
            }
            return configEntries;
        }

        @Override
        public String toString() {
            return "config-file " + Utils.jsonSerializeForLog(file);
        }
    }
}
