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
package com.yahoo.athenz.auth.oauth.util;

import static org.testng.Assert.*;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import jakarta.servlet.http.HttpServletRequest;
import org.mockito.Mockito;
import org.testng.annotations.Test;

public class OAuthAuthorityUtilsTest {

    @Test
    public void testGetProperty() {

        // prop not set
        System.clearProperty("athenz.auth.oauth.jwt.test_prop");
        String propValue = OAuthAuthorityUtils.getProperty("test_prop", null);
        assertNull(propValue);
        propValue = OAuthAuthorityUtils.getProperty("test_prop", "");
        assertEquals(propValue, "");
        propValue = OAuthAuthorityUtils.getProperty("test_prop", "default_value");
        assertEquals(propValue, "default_value");

        // prop set
        System.setProperty("athenz.auth.oauth.jwt.test_prop", "test_value");
        propValue = OAuthAuthorityUtils.getProperty("test_prop", null);
        assertEquals(propValue, "test_value");
        propValue = OAuthAuthorityUtils.getProperty("test_prop", "");
        assertEquals(propValue, "test_value");
        propValue = OAuthAuthorityUtils.getProperty("test_prop", "default_value");
        assertEquals(propValue, "test_value");
        System.clearProperty("athenz.auth.oauth.jwt.test_prop");
    }

    @Test
    public void testCsvToSet() {

        // empty csv
        Set<String> propValue = OAuthAuthorityUtils.csvToSet(null, ",");
        assertNull(propValue);
        propValue = OAuthAuthorityUtils.csvToSet("", ",");
        assertNull(propValue);
        // empty delimiter
        propValue = OAuthAuthorityUtils.csvToSet("csv_1,csv_2", null);
        assertEquals(propValue, new HashSet<>(Arrays.asList("csv_1,csv_2")));
        propValue = OAuthAuthorityUtils.csvToSet("csv_1,csv_2", "");
        assertEquals(propValue, new HashSet<>(Arrays.asList("csv_1,csv_2")));
        // string delimiter
        propValue = OAuthAuthorityUtils.csvToSet("csv_1,csv_2", ",");
        assertEquals(propValue, new HashSet<>(Arrays.asList("csv_1", "csv_2")));
        propValue = OAuthAuthorityUtils.csvToSet("csv_1,csv_2", "_");
        assertEquals(propValue, new HashSet<>(Arrays.asList("csv", "1,csv", "2")));
        propValue = OAuthAuthorityUtils.csvToSet("csv_1,csv_2,", ",");
        assertEquals(propValue, new HashSet<>(Arrays.asList("csv_1", "csv_2")));
        // regex delimiter
        propValue = OAuthAuthorityUtils.csvToSet("csv_1,csv_2", "\\d");
        assertEquals(propValue, new HashSet<>(Arrays.asList("csv_", ",csv_")));
        propValue = OAuthAuthorityUtils.csvToSet("csv_1,csv_2,csv_3", "\\d");
        assertEquals(propValue, new HashSet<>(Arrays.asList("csv_", ",csv_")));
    }

    @Test
    public void testExtractHeaderToken() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        // strict bearer token
        Enumeration<String> headers = Collections.enumeration(Arrays.asList("Bearer dummy_access_token_1"));
        Mockito.when(request.getHeaders("Authorization")).thenReturn(headers);
        String tokenString = OAuthAuthorityUtils.extractHeaderToken(request);
        assertEquals(tokenString, "dummy_access_token_1");

        // case-insensitive bearer token
        headers = Collections.enumeration(Arrays.asList("bearer dummy_access_token_2"));
        Mockito.when(request.getHeaders("Authorization")).thenReturn(headers);
        tokenString = OAuthAuthorityUtils.extractHeaderToken(request);
        assertEquals(tokenString, "dummy_access_token_2");

        // multiple bearer token
        headers = Collections.enumeration(Arrays.asList("Bearer dummy_access_token_3,dummy_access_token_4"));
        Mockito.when(request.getHeaders("Authorization")).thenReturn(headers);
        tokenString = OAuthAuthorityUtils.extractHeaderToken(request);
        assertEquals(tokenString, "dummy_access_token_3");

        // empty header
        Mockito.when(request.getHeaders("Authorization")).thenReturn(Collections.emptyEnumeration());
        tokenString = OAuthAuthorityUtils.extractHeaderToken(request);
        assertNull(tokenString);

        // non-bearer header
        headers = Collections.enumeration(Arrays.asList("Basic encoded_password"));
        Mockito.when(request.getHeaders("Authorization")).thenReturn(headers);
        tokenString = OAuthAuthorityUtils.extractHeaderToken(request);
        assertNull(tokenString);
    }

    @Test
    public void testPrivateConstructor() throws Exception {
        Constructor<OAuthAuthorityUtils> constructor = OAuthAuthorityUtils.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        constructor.setAccessible(true);
        constructor.newInstance();
    }

}
