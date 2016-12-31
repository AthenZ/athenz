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
package com.yahoo.athenz.zpe_policy_updater;

import java.io.IOException;

import com.yahoo.athenz.sia.SIA;
import com.yahoo.athenz.zpe_policy_updater.SIAClientFactory;

public class DebugSIAClientFactory implements SIAClientFactory {

    private boolean emptyDomainList;
    
    public DebugSIAClientFactory() {
        emptyDomainList = false;
    }
    
    public DebugSIAClientFactory(boolean emptyList) {
        emptyDomainList = emptyList;
    }
    @Override
    public SIA create() throws IOException {
        return new SIAClientMock(emptyDomainList);
    }

}
