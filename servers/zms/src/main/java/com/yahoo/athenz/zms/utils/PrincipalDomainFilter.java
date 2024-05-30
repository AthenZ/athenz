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

package com.yahoo.athenz.zms.utils;

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.Principal;
import org.eclipse.jetty.util.StringUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class PrincipalDomainFilter {

    Set<String> allowedDomains;
    List<String> disallowedSubDomains;
    List<String> allowedSubDomains;

    public PrincipalDomainFilter(final String domainFilter) {

        // supported format is domainName,+domainName,-domainName

        if (StringUtil.isEmpty(domainFilter)) {
            return;
        }

        // for matching with domains and not substrings we're going
        // to automatically add a '.' at the end of each domain name

        String[] domainNames = domainFilter.split(",");
        for (String domainName : domainNames) {
            if (domainName.startsWith("+")) {
                if (allowedSubDomains == null) {
                    allowedSubDomains = new ArrayList<>();
                }
                allowedSubDomains.add(domainName.substring(1) + ".");
            } else if (domainName.startsWith("-")) {
                if (disallowedSubDomains == null) {
                    disallowedSubDomains = new ArrayList<>();
                }
                disallowedSubDomains.add(domainName.substring(1) + ".");
            } else {
                if (allowedDomains == null) {
                    allowedDomains = new HashSet<>();
                }
                allowedDomains.add(domainName + ".");
            }
        }
    }
    
    public boolean validate(final String principalName, Principal.Type type) {
            
        // if we have no filter then we're good
        
        if (allowedDomains == null && allowedSubDomains == null && disallowedSubDomains == null) {
            return true;
        }

        // let's first extract our domain name: special handling
        // for groups while all other types are standard service names
        // since we're given the principal type, it's already been
        // verified that the principal name is valid so no need to
        // check for error cases

        int idx = getIdx(principalName, type);
        final String domainName = principalName.substring(0, idx) + ".";

        // if we have disallowed domains then we need to make sure
        // that the principal domain is not in the disallowed list

        if (disallowedSubDomains != null) {

            for (String disallowedDomain : disallowedSubDomains) {
                if (domainName.startsWith(disallowedDomain)) {
                    return false;
                }
            }

            // at this time we don't have any allowed list specified
            // it means all other entries are allowed

            if (allowedDomains == null && allowedSubDomains == null) {
                return true;
            }
        }

        // if we have allowed domains then we need to make sure
        // that the principal domain is in the allowed list
        
        if (allowedDomains != null) {
            if (allowedDomains.contains(domainName)) {
                return true;
            }

            // at this time we don't have any subdomains specified
            // it means all other entries are disallowed

            if (allowedSubDomains == null) {
                return false;
            }
        }

        // if we got here it means we have configured allowed subdomains,
        // so we need to make sure the principal domain is in the allowed list
        
        for (String allowedDomain : allowedSubDomains) {
            if (domainName.startsWith(allowedDomain)) {
                return true;
            }
        }

        return false;
    }

    private int getIdx(String principalName, Principal.Type type) {
        int idx;
        if (type == Principal.Type.GROUP) {
            idx = principalName.indexOf(AuthorityConsts.GROUP_SEP);
        } else {
            idx = principalName.lastIndexOf('.');
        }
        return idx;
    }
}
