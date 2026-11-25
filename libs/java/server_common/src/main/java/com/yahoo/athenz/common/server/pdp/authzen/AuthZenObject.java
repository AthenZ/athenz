/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.pdp.authzen;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Base class for all AuthZEN model objects. Unknown JSON members received
 * from a PDP are preserved as extensions instead of failing the parse, so
 * PDPs that extend the AuthZEN specification remain interoperable.
 */
public abstract class AuthZenObject {

    private final Map<String, Object> extensions = new LinkedHashMap<>();

    @JsonAnySetter
    void setExtension(final String name, final Object value) {
        extensions.put(name, value);
    }

    /**
     * @return unmodifiable map of JSON members not defined by the AuthZEN model
     */
    @JsonAnyGetter
    public Map<String, Object> getExtensions() {
        return Collections.unmodifiableMap(extensions);
    }

    static Map<String, Object> copyOf(final Map<String, Object> map) {
        return map == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(map));
    }

    static <T> List<T> copyOf(final List<T> list) {
        return list == null ? null : Collections.unmodifiableList(new ArrayList<>(list));
    }
}
