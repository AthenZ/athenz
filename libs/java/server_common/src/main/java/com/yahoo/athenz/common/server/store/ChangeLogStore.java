/*
 *  Copyright 2020 Verizon Media
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.store;

import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;

import java.util.List;
import java.util.Set;

/**
 * An interface that ZTSCore depends on to manage its state.
 */
public interface ChangeLogStore {

    /**
     * Gets the associated local domain data for the key
     * @param domainName the name of the domain
     * @return SignedDomain object of the domain or null if absent
     */
    SignedDomain getLocalSignedDomain(String domainName);

    /**
     * Gets the associated server domain data for the key
     * @param domainName the name of the domain
     * @return SignedDomain object of the domain or null if absent
     */
    SignedDomain getServerSignedDomain(String domainName);

    /**
     * Remove the local domain record from the changelog store
     * @param domainName the name of the domain
     */
    void removeLocalDomain(String domainName);

    /**
     * Save the local domain record from the changelog store
     * @param domainName the name of the domain
     * @param signedDomain the {@code SignedDomain} for the {@code domainName} supplied
     */
    void saveLocalDomain(String domainName, SignedDomain signedDomain);

    /**
     * Returns the names of all domain stored in local repository
     * @return List of domain names
     */
    List<String> getLocalDomainList();

    /**
     * Returns the list of all domains configured on server
     * @return Set of domain names
     */
    Set<String> getServerDomainList();

    /**
     * Returns the list of domains configured on the server
     * with their meta attributes only - primary interest being
     * the last modification timestamp
     * @return Array of SignedDomain objects
     */
    SignedDomains getServerDomainModifiedList();

    /**
     * Returns the list of domains modified since the last call
     * @param lastModTimeBuffer StringBuilder object will be updated to include
     * the last modification time for the request. If data store
     * successfully updates the local entries in the cache then
     * it will call setLastModificationTimestamp with the same value
     * @return Array of SignedDomain objects
     */
    SignedDomains getUpdatedSignedDomains(StringBuilder lastModTimeBuffer);

    /**
     * Notifies the store to update its changelog last modification
     * timestamp. If the value is null then it notifies the stores to
     * reset its changelog and during next retrieveDomainUpdates call
     * to return set of all domains available in ZMS
     * @param lastModTime last modification timestamp
     */
    void setLastModificationTimestamp(String lastModTime);

    /**
     * The change log store supports getting a full refresh from
     * ZMS Server directly
     * @return true if store supports full refresh, false otherwise
     */
    boolean supportsFullRefresh();

    /**
     * Allow requesting conditions from ZMS.
     * Default implementation does not take any action.
     */
    default void setRequestConditions(boolean requestConditions) {
    }
}
