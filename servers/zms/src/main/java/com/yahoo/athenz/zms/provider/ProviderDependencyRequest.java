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

package com.yahoo.athenz.zms.provider;

public class ProviderDependencyRequest {
    String operation;
    String domainName;
    String objectType;
    String objectName;
    String principal;
    String provider;

    public ProviderDependencyRequest(String operation, String domainName, String objectType, String objectName, String principal, String provider) {
        this.operation = operation;
        this.domainName = domainName;
        this.objectType = objectType;
        this.objectName = objectName;
        this.principal = principal;
        this.provider = provider;
    }

    public String getOperation() {
        return operation;
    }

    public String getDomainName() {
        return domainName;
    }

    public String getObjectType() {
        return objectType;
    }

    public String getObjectName() {
        return objectName;
    }

    public String getPrincipal() {
        return principal;
    }

    public String getProvider() {
        return provider;
    }
}
