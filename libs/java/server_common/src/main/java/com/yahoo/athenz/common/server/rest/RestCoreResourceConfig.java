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
import java.util.HashMap;

import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.glassfish.hk2.utilities.binding.AbstractBinder;

/*
 * This is used to setup the application configuration for authorities,
 * authorizer, supported content-providers, and delegate.
 */
public class RestCoreResourceConfig extends ResourceConfig {

    // map of authorizer and authority objects
    @SuppressWarnings("rawtypes")
    HashMap<Class, Object> authObjMap = new HashMap<Class, Object>();

    // typically contains delegate binding (AbstractBinder)
    //
    HashSet<Object>        singletons;


    public RestCoreResourceConfig(HashSet<Class<?>> resources, HashSet<Object> singletonSet) {
        if (resources == null || resources.isEmpty()) {
            throw new ResourceException(ResourceException.BAD_REQUEST, "Missing required parameter: resources");
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

    // for setting Authority list and Authorizer
    @SuppressWarnings("rawtypes")
    public void setAuthorityObject(Class klassType, Object authObj) {
        authObjMap.put(klassType, authObj);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public void registerAll() {
        // register the authority objects
        if (authObjMap.isEmpty()) {
            throw new ResourceException(ResourceException.BAD_REQUEST, "Missing required parameter: authorizer or authorities");
        }

        AbstractBinder binder = new AbstractBinder() {
            final HashMap<Class, Object> authMap = authObjMap;

            @Override
            protected void configure() {
                for (Class klass: authMap.keySet()) {
                    bind(klass).in(javax.inject.Singleton.class);
                    bind(klass.cast(authMap.get(klass))).to(klass);
                }
            }
        };
        registerInstances(binder);

        if (singletons == null || singletons.isEmpty()) {
            throw new ResourceException(ResourceException.BAD_REQUEST, "Missing required parameter: singletons (delegate for the resource)");
        }

        // register the singletons
        for (Object singletonObj : singletons) {
            registerInstances(singletonObj);
        }
    }
}

