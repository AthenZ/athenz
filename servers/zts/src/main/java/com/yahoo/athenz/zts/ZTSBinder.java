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
package com.yahoo.athenz.zts;

import org.glassfish.jersey.internal.inject.AbstractBinder;

public class ZTSBinder extends AbstractBinder  {

    private final static ZTSBinder ZTS_BINDER_INSTANCE = new ZTSBinder();

    private final ZTSImpl ztsImpl;

    private ZTSBinder() {
        this.ztsImpl = ZTSImplFactory.getZtsInstance();
    }

    @Override
    protected void configure() {
        bind(ztsImpl).to(ZTSHandler.class);
    }

    public static ZTSBinder getInstance() {
        return ZTS_BINDER_INSTANCE;
    }
}
