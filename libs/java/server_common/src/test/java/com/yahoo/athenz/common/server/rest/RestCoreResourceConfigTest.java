/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.common.server.rest;

import java.util.HashSet;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.rest.ResourceException;
import com.yahoo.athenz.common.server.rest.RestCoreResourceConfig;

import static org.testng.Assert.*;

/*
 * This is used to setup the application configuration for authorities,
 * authorizer, supported content-providers, and delegate.
 */
public class RestCoreResourceConfigTest {

    @SuppressWarnings({ "rawtypes", "unchecked", "unused" })
    @Test
    public void testRestCoreResourceConfigBadRequest() {
        HashSet hashSet = Mockito.mock(HashSet.class);
        try {
            RestCoreResourceConfig restCoreResourceConfig = new RestCoreResourceConfig(null, hashSet);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 400);
        }
    }

    @SuppressWarnings("unused")
    @Test
    public void testsetSingletonsNull() {
        HashSet<Class<?>> resources  = new HashSet<Class<?>>();
        HashSet<Object> singletons = new HashSet<Object>();
        try {
            RestCoreResourceConfig restCoreResourceConfig = new RestCoreResourceConfig(resources, singletons);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 400);
        }
    }
}
