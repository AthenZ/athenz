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
package com.yahoo.athenz.container.config;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Configuration for an allowed endpoint including path (exact or prefix/suffix), HTTP methods, and description.
 * Use "path" for exact match, or "path_starts_with" and/or "path_ends_with" for prefix/suffix matching.
 */
public class EndpointConfig {

    private String path;
    @JsonProperty("path_starts_with")
    private String pathStartsWith;
    @JsonProperty("path_ends_with")
    private String pathEndsWith;
    private List<String> methods;
    private String description;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getPathStartsWith() {
        return pathStartsWith;
    }

    public void setPathStartsWith(String pathStartsWith) {
        this.pathStartsWith = pathStartsWith;
    }

    public String getPathEndsWith() {
        return pathEndsWith;
    }

    public void setPathEndsWith(String pathEndsWith) {
        this.pathEndsWith = pathEndsWith;
    }

    public List<String> getMethods() {
        return methods;
    }

    public void setMethods(List<String> methods) {
        this.methods = methods;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Check if this endpoint allows the given HTTP method
     *
     * @param method HTTP method to check
     * @return true if method is allowed (or if no method restrictions configured)
     */
    public boolean allowsMethod(String method) {
        return methods == null || methods.isEmpty() || methods.contains(method);
    }
}
