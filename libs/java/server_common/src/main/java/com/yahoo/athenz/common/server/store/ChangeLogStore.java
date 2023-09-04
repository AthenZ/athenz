/*
 *  Copyright The Athenz Authors
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

import com.yahoo.athenz.zms.DomainAttributes;
import com.yahoo.athenz.zms.JWSDomain;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;

import java.util.List;
import java.util.Map;
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
     * Gets the associated local domain data for the key
     * @param domainName the name of the domain
     * @return JWSDomain object of the domain or null if absent
     */
    default JWSDomain getLocalJWSDomain(String domainName) {
        return null;
    }

    /**
     * Gets the associated server domain data for the key
     * @param domainName the name of the domain
     * @return SignedDomain object of the domain or null if absent
     */
    SignedDomain getServerSignedDomain(String domainName);

    /**
     * Gets the associated server domain data for the key
     * @param domainName the name of the domain
     * @return JWSDomain object of the domain or null if absent
     */
    default JWSDomain getServerJWSDomain(String domainName) {
        return null;
    }

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
     * Save the local domain record from the changelog store
     * @param domainName the name of the domain
     * @param jwsDomain the {@code JWSDomain} for the {@code domainName} supplied
     */
    default void saveLocalDomain(String domainName, JWSDomain jwsDomain) {
    }

    /**
     * Returns the names of all domain stored in local repository
     * @return List of domain names
     */
    List<String> getLocalDomainList();

    /**
     * Returns the names of all domain stored in local repository
     * along with domain attributes (e.g. timestamp when the domain was fetched).
     * @return Map of domain names with their attributes
     */
    default Map<String, DomainAttributes> getLocalDomainAttributeList() {
        return null;
    }

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
     * Returns the list of domains modified since the last call
     * @param lastModTimeBuffer StringBuilder object will be updated to include
     * the last modification time for the request. If data store
     * successfully updates the local entries in the cache then
     * it will call setLastModificationTimestamp with the same value
     * @return List of JWSDomain objects
     */
    default List<JWSDomain> getUpdatedJWSDomains(StringBuilder lastModTimeBuffer) {
        return null;
    }

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
     * @param requestConditions boolean flag to request conditions
     */
    default void setRequestConditions(boolean requestConditions) {
    }

    /**
     * Enable JWS Domain support instead of Signed Domains which
     * use canonical form of json to generate signatures
     * @param jwsDomainSupport boolean flag to enable support for jws domain objects
     */
    default void setJWSDomainSupport(boolean jwsDomainSupport) {
    }
}
