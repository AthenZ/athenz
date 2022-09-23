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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.testng.annotations.Test;

import java.util.List;

import static org.testng.Assert.*;

public class AuthzDetailsEntityListTest {

    @Test
    public void testAthenzDetailsEntityList() throws JsonProcessingException {

        final String jsonData = "{\"entities\": [{\"type\":\"message_access\",\"fields\":[{\"name\":\"location\",\"optional\":true}," +
                "{\"name\":\"identifier\",\"optional\":false},{\"name\":\"resource\"}]}," +
                "{\"type\":\"proxy_access\",\"fields\":[{\"name\":\"principal\",\"optional\":true}]}]}";

        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

        AuthzDetailsEntityList entityList = jsonMapper.readValue(jsonData, AuthzDetailsEntityList.class);
        assertNotNull(entityList);
        assertEquals(entityList.getEntities().size(), 2);

        assertEquals(entityList.getEntities().get(0).getType(), "message_access");

        List<AuthzDetailsField> fields = entityList.getEntities().get(0).getFields();
        assertNotNull(fields);
        assertEquals(fields.size(), 3);

        assertEquals(fields.get(0).getName(), "location");
        assertTrue(fields.get(0).isOptional());

        assertEquals(fields.get(1).getName(), "identifier");
        assertFalse(fields.get(1).isOptional());

        assertEquals(fields.get(2).getName(), "resource");
        assertFalse(fields.get(2).isOptional());

        // validate second entry

        assertEquals(entityList.getEntities().get(1).getType(), "proxy_access");

        fields = entityList.getEntities().get(1).getFields();
        assertNotNull(fields);
        assertEquals(fields.size(), 1);

        assertEquals(fields.get(0).getName(), "principal");
        assertTrue(fields.get(0).isOptional());
    }
}
