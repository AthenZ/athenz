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

package com.yahoo.athenz.common.messaging;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

public class DomainChangePublisherFactory {

    public static final String ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_CLASS = "athenz.zms.domain_change_publisher_class";
    public static final String ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_DEFAULT = "com.yahoo.athenz.common.messaging.NoOpDomainChangePublisher";

    private static DomainChangePublisher createPublisher() {
        DomainChangePublisher instance;
        String paramStoreClassName = System.getProperty(ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_CLASS, ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_DEFAULT);
        try {
            Constructor<?> ctor = Class.forName(paramStoreClassName).getConstructor();
            instance = (DomainChangePublisher) ctor.newInstance();
        } catch (NoSuchMethodException | ClassNotFoundException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
            throw new ExceptionInInitializerError(e);
        }
        return instance;
    }

    /**
     * Creates the domain change publisher
     * @return domain change publisher
     */
    public static DomainChangePublisher create() {
        return createPublisher();
    }
}
