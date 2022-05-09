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

import jakarta.annotation.Nullable;
import java.util.Collection;

/** Knows to build config-sources for relevant source-descriptions */
public abstract class ConfigProvider {

    /** Given a source-description - if it is relevant for this provider - build a config-source */
    public abstract @Nullable ConfigSource tryToBuildConfigSource(String sourceDescription) throws Exception;

    @Override
    public String toString() {
        return this.getClass().getName().replaceFirst(".*\\.", "");
    }

    /** A source of configurations - each is made of a string key, and a string value */
    public static abstract class ConfigSource {

        public final String sourceDescription;

        protected ConfigSource(String sourceDescription) {
            this.sourceDescription = sourceDescription;
        }

        /** Get all configuration entries of the source */
        public abstract Collection<ConfigEntry> getConfigEntries() throws Exception;

        @Override
        public abstract String toString();
    }
}
