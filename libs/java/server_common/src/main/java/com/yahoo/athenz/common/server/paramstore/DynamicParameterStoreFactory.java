/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.paramstore;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

public class DynamicParameterStoreFactory {

    public static final String DYNAMIC_PARAM_STORE_CLASS = "athenz.common.server.dynamic_param_store_class";
    public static final String PROP_AWS_PARAM_STORE_CLASS_DEFAULT = "com.yahoo.athenz.common.server.paramstore.NoOpParameterStore";

    //Singleton holder
    static class IDynamicParameterHolder {
        static DynamicParameterStore instance = createDynamicParameterStore(); // This will be lazily initialised
    }

    private static DynamicParameterStore createDynamicParameterStore() {
        DynamicParameterStore instance;
        String paramStoreClassName = System.getProperty(DYNAMIC_PARAM_STORE_CLASS, PROP_AWS_PARAM_STORE_CLASS_DEFAULT);
        try {
            Constructor<?> ctor = Class.forName(paramStoreClassName).getConstructor();
            instance = (DynamicParameterStore) ctor.newInstance();
        } catch (NoSuchMethodException | ClassNotFoundException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
            throw new ExceptionInInitializerError(e);
        }
        return instance;
    }

    public static DynamicParameterStore create() {
        return getInstance();
    }

    public static DynamicParameterStore getInstance() {
        if (IDynamicParameterHolder.instance == null) {
            IDynamicParameterHolder.instance = createDynamicParameterStore();
        }
        return IDynamicParameterHolder.instance;
    }
    
}
