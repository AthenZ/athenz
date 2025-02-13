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
package com.yahoo.athenz.auth;

import java.security.PublicKey;

/**
 * The interface for a public key provider.
 */
public interface PublicKeyProvider {

    /**
     * @param domainName the name of the domain
     * @param serviceName the name of the service
     * @param keyId the key id for the registered public key
     * @return the registered public key for the service with the given key id.
     */
    PublicKey getServicePublicKey(String domainName, String serviceName, String keyId);

}
