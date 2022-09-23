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

public interface KeyStore {
    
    /**
     * Return the PEM encoded public key for the given key id and service.
     * The key which should be ybase64decoded prior to return if was ybase64encoded.
     * @param domain Name of the domain
     * @param service Name of the service
     * @param keyId the public key identifier
     * @return String with PEM encoded key
     */
    String getPublicKey(String domain, String service, String keyId);
}
