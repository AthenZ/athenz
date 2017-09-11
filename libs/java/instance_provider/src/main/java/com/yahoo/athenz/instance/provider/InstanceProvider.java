/**
 * Copyright 2017 Yahoo Holdings, Inc.
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
package com.yahoo.athenz.instance.provider;

public interface InstanceProvider {

    /**
     * Set provider details and initialize the provider object
     * @param provider name of the provider (service identity name)
     * @param endpoint endpoint for the provider
     */
    public void initialize(String provider, String endpoint);
    
    /**
     * Contact the Instance provider and confirm that the requested
     * instance details are valid in order for ZTS to issue a
     * service identity certificate for the instance
     * @param confirmation instance confirmation details (including instance
     * identity document, its signature and other details)
     * @return InstanceConfirmation object if the confirmation is successful
     * @throws ResourceException in case of any errors
     */
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation);
    
    /**
     * Close the client and, if necessary, release any allocated resources
     */
    default public void close() {
    }
}
