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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * AuthZEN Subject: the principal on whose behalf the decision is requested.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class Subject extends AuthZenObject {

    private final String type;
    private final String id;
    private final Map<String, Object> properties;

    /**
     * @param type subject type (e.g. user, service)
     * @param id subject identifier
     * @param properties optional subject attributes
     */
    @JsonCreator
    public Subject(@JsonProperty("type") final String type, @JsonProperty("id") final String id,
            @JsonProperty("properties") final Map<String, Object> properties) {
        this.type = type;
        this.id = id;
        this.properties = copyOf(properties);
    }

    public String getType() {
        return type;
    }

    public String getId() {
        return id;
    }

    public Map<String, Object> getProperties() {
        return properties;
    }
}
