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
package com.yahoo.athenz.common.config;

import static org.testng.Assert.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.testng.annotations.Test;

import java.util.List;

public class AuthzDetailsTest {

    @Test
    public void testAthenzDetailsEntity() throws JsonProcessingException {

        final String jsonData = "{\"type\":\"message_access\",\"roles\":[{\"name\":\"msg-readers\"," +
                "\"optional\":true},{\"name\":\"msg-writers\",\"optional\":false},{\"name\":" +
                "\"msg-editors\"}],\"fields\":[{\"name\":\"location\",\"optional\":true}," +
                "{\"name\":\"identifier\",\"optional\":false},{\"name\":\"resource\"}]}";

        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

        AuthzDetailsEntity entity = jsonMapper.readValue(jsonData, AuthzDetailsEntity.class);
        assertNotNull(entity);
        assertEquals(entity.getType(), "message_access");

        List<AuthzDetailsField> roles = entity.getRoles();
        assertNotNull(roles);
        assertEquals(roles.size(), 3);

        assertEquals(roles.get(0).getName(), "msg-readers");
        assertTrue(roles.get(0).isOptional());

        assertEquals(roles.get(1).getName(), "msg-writers");
        assertFalse(roles.get(1).isOptional());

        assertEquals(roles.get(2).getName(), "msg-editors");
        assertFalse(roles.get(2).isOptional());

        List<AuthzDetailsField> fields = entity.getFields();
        assertNotNull(fields);
        assertEquals(fields.size(), 3);

        assertEquals(fields.get(0).getName(), "location");
        assertTrue(fields.get(0).isOptional());

        assertEquals(fields.get(1).getName(), "identifier");
        assertFalse(fields.get(1).isOptional());

        assertEquals(fields.get(2).getName(), "resource");
        assertFalse(fields.get(2).isOptional());

        // valid and invalid field names

        assertTrue(entity.isValidField("location"));
        assertTrue(entity.isValidField("identifier"));
        assertTrue(entity.isValidField("resource"));

        assertFalse(entity.isValidField("uuid"));
    }

    @Test
    public void testAthenzDetailsEntityInvalidJson() {

        final String jsonData = "{\"type\":\"message_access\",\"roles\":[{\"name\"";

        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

        try {
            jsonMapper.readValue(jsonData, AuthzDetailsEntity.class);
            fail();
        } catch (JsonProcessingException ignored) {
        }
    }

    @Test
    public void testAthenzDetailsEntityOptionalFields() throws JsonProcessingException {

        final String jsonData = "{\"type\":\"message_access\"}";

        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

        AuthzDetailsEntity entity = jsonMapper.readValue(jsonData, AuthzDetailsEntity.class);
        assertNotNull(entity);
        assertEquals(entity.getType(), "message_access");
        assertNull(entity.getRoles());
        assertNull(entity.getFields());
    }

    @Test
    public void testAthenzDetailsEntityUnknownFields() {

        final String jsonData = "{\"type\":\"message_access\",\"data\":\"test\"}";

        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

        try {
            jsonMapper.readValue(jsonData, AuthzDetailsEntity.class);
            fail();
        } catch (JsonProcessingException ignored) {
        }
    }

    @Test
    public void testIsValidFieldNull() {
        AuthzDetailsEntity entity = new AuthzDetailsEntity();
        assertNull(entity.getFields());

        assertFalse(entity.isValidField("type"));
    }
}
