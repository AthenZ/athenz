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
package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.zms.config.SolutionTemplates;
import com.yahoo.rdl.Validator;

import java.util.List;

public class ZMSConfig {

    private String serverHostName;
    private String userDomain;
    private String userDomainPrefix;
    private String headlessUserDomainPrefix;
    private List<String> addlUserCheckDomainPrefixList;
    private SolutionTemplates serverSolutionTemplates;
    private Authority userAuthority;
    private Validator validator;

    public String getUserDomain() {
        return userDomain;
    }

    public void setUserDomain(String userDomain) {
        this.userDomain = userDomain;
    }

    public String getUserDomainPrefix() {
        return userDomainPrefix;
    }

    public void setUserDomainPrefix(String userDomainPrefix) {
        this.userDomainPrefix = userDomainPrefix;
    }

    public String getHeadlessUserDomainPrefix() {
        return headlessUserDomainPrefix;
    }

    public void setHeadlessUserDomainPrefix(String headlessUserDomainPrefix) {
        this.headlessUserDomainPrefix = headlessUserDomainPrefix;
    }

    public List<String> getAddlUserCheckDomainPrefixList() {
        return addlUserCheckDomainPrefixList;
    }

    public void setAddlUserCheckDomainPrefixList(List<String> addlUserCheckDomainPrefixList) {
        this.addlUserCheckDomainPrefixList = addlUserCheckDomainPrefixList;
    }

    public String getServerHostName() {
        return serverHostName;
    }

    public void setServerHostName(String serverHostName) {
        this.serverHostName = serverHostName;
    }

    public SolutionTemplates getServerSolutionTemplates() {
        return serverSolutionTemplates;
    }

    public void setServerSolutionTemplates(SolutionTemplates serverSolutionTemplates) {
        this.serverSolutionTemplates = serverSolutionTemplates;
    }

    public Authority getUserAuthority() {
        return userAuthority;
    }

    public void setUserAuthority(Authority userAuthority) {
        this.userAuthority = userAuthority;
    }

    public Validator getValidator() {
        return validator;
    }

    public void setValidator(Validator validator) {
        this.validator = validator;
    }
}
