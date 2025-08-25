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
package io.athenz.syncer.common.zms;


/**
 * Interface for managing domain data in a cloud-based store.
 */
public interface CloudDomainStore {

    /**
     * Uploads the specified domain data to the cloud store.
     *
     * @param domainName the name of the domain to upload
     * @param domJson the domain data in JSON format
     */
    void uploadDomain(final String domainName, final String domJson);

    /**
     * Deletes the specified domain from the cloud store.
     *
     * @param domainName the name of the domain to delete
     */
    void deleteDomain(final String domainName);

}


