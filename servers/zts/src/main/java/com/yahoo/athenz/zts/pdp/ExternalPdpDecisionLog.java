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

package com.yahoo.athenz.zts.pdp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Structured decision log for external PDP evaluations. Uses a dedicated
 * logger so operators can route the entries to an audit sink. Entries
 * never include token values or claim values.
 */
public final class ExternalPdpDecisionLog {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExternalPdpDecisionLog.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Map<String, Object> fields = new LinkedHashMap<>();

    /**
     * @param requestId pdp request id
     * @param mode operating mode
     * @param flow token flow
     */
    public ExternalPdpDecisionLog(final String requestId, final ExternalPdpMode mode, final String flow) {
        fields.put("request_id", requestId);
        fields.put("mode", mode.name());
        fields.put("flow", flow);
    }

    /**
     * Add a field to the entry; null values are skipped.
     * @param name field name
     * @param value field value
     * @return this entry
     */
    public ExternalPdpDecisionLog with(final String name, final Object value) {
        if (value != null) {
            fields.put(name, value);
        }
        return this;
    }

    Map<String, Object> getFields() {
        return fields;
    }

    /**
     * Write the entry to the decision log.
     */
    public void write() {
        String entry;
        try {
            entry = MAPPER.writeValueAsString(fields);
        } catch (JsonProcessingException ex) {
            entry = fields.toString();
        }
        LOGGER.info("pdp_decision {}", entry);
    }
}
