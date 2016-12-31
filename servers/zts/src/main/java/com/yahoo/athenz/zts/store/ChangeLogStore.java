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
package com.yahoo.athenz.zts.store;

import java.util.List;
import java.util.Set;

import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;

/**
 * An interface that ZTSCore depends on to manage its state.
 */

public interface ChangeLogStore {
    
    /**
     * Gets the associated domain data for the key
     * @param domainName the name of the domain
     * @return SignedDomain object of the domain or null if absent
     */
    public SignedDomain getSignedDomain(String domainName);
    
    /**
     * Remove the local domain record from the changelog store
     * @param domainName the name of the domain
     */
    public void removeLocalDomain(String domainName);
    
    /**
     * Save the local domain record from the changelog store
     * @param domainName the name of the domain
     * @param signedDomain the {@code SignedDomain} for the {@code domainName} supplied
     */
    public void saveLocalDomain(String domainName, SignedDomain signedDomain);
    
    /**
     * Returns the names of all domain stored in local repository
     * @return List of domain names
     */
    public List<String> getLocalDomainList();
    
    /**
     * Returns the list of all domains configured on server
     * @return Set of domain names
     */
    public Set<String> getServerDomainList();
    
    /**
     * Returns the list of domains modified since the last call
     * @param lastModTimeBuffer StringBuilder object will be updated to include
     * the last modification time for the request. If data store
     * successfully updates the local entries in the cache then
     * it will call setLastModificationTimestamp with the same value
     * @return Array of SignedDomain objects
     */
    public SignedDomains getUpdatedSignedDomains(StringBuilder lastModTimeBuffer);
    
    /**
     * Notifies the store to update its changelog last modification
     * timestamp. If the value is null then it notifies the stores to
     * reset its changelog and during next retrieveDomainUpdates call
     * to return set of all domains available in ZMS
     * @param lastModTime last modification timestamp
     */
    public void setLastModificationTimestamp(String lastModTime);
    
    /**
     * The change log store supports getting a full refresh from
     * ZMS Server directly
     * @return true if store supports full refresh, false otherwise
     */
    public boolean supportsFullRefresh();
}
