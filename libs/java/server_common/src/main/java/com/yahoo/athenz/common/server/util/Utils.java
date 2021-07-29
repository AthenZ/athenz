package com.yahoo.athenz.common.server.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Utils {

    /** Convert a value to JSON - or return a human-readable error if failed */
    public static String jsonSerializeForLog(Object value) {
        try {
            return OBJECT_MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            return "=== Can't JSON-ize a " + value.getClass().getName() + " ===";
        }
    }


    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
}
