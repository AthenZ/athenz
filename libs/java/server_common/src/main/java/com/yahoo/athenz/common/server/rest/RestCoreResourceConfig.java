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

import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.jackson.JacksonFeature;

/*
 * This is used to setup the application configuration delegate.
 */
public class RestCoreResourceConfig extends ResourceConfig {

    // typically contains delegate binding (AbstractBinder)

    HashSet<Object> singletons;

    public RestCoreResourceConfig(HashSet<Class<?>> resources, HashSet<Object> singletonSet) {
        if (resources == null || resources.isEmpty()) {
            throw new ResourceException(ResourceException.BAD_REQUEST,
                    "Missing required parameter: resources");
        }

        StringBuilder packageList = new StringBuilder(256);
        int pkgCnt = 0;
        for (Class<?> klass: resources) {
            Package pkg = klass.getPackage();
            if (pkg == null) {
                continue;
            }

            String pkgName = pkg.getName();
            if (pkgName == null || pkgName.length() == 0) {
                continue;
            }

            if (pkgCnt > 0) {
                packageList.append(";");
            }
            packageList.append(pkgName);
            ++pkgCnt;
        }

        setupPackages(packageList.toString());

        setSingletons(singletonSet);
    }
    
    void setupPackages(String packageList) {
        packages(packageList)
            .register(JacksonFeature.class);
    }

    public void setSingletons(HashSet<Object> singletonSet) {
        if (singletonSet == null) {
            return;
        } else if (singletons == null) {
            singletons = singletonSet;
        } else {
            for (Object singletonObj : singletonSet) {
                singletons.add(singletonObj);
            }
        }
    }

    public void registerAll() {

        if (singletons == null || singletons.isEmpty()) {
            throw new ResourceException(ResourceException.BAD_REQUEST,
                    "Missing required parameter: singletons (delegate for the resource)");
        }

        // register the singletons
        for (Object singletonObj : singletons) {
            registerInstances(singletonObj);
        }
    }
}

