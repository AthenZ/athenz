/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import {
    addAssertionPolicyVersionToStore,
    deleteAssertionPolicyVersionFromStore,
    loadPolicies,
} from '../redux/actions/policies';
import { getExpiryTime } from '../redux/utils';
import { storeDomainData, storePolicies } from '../redux/actions/domains';
import { loadDomainData } from '../redux/actions/domain-data';

export const getLoadDomainDataAction = (domainName, domainData) => {
    return loadDomainData(domainData, domainName, getExpiryTime());
};

export const getStoreDomainDataAction = (domainData) => {
    return storeDomainData(domainData);
};

export const getLoadPoliciesAction = (domainName, policies = {}) => {
    return loadPolicies(policies, domainName, getExpiryTime());
};

export const getStorePoliciesAction = (policiesData) => {
    return storePolicies(policiesData);
};

export const getDeleteAssertionPolicyVersionAction = (
    policyName,
    version,
    assertionId
) => {
    return deleteAssertionPolicyVersionFromStore(
        policyName,
        version,
        assertionId
    );
};

export const getAddAssertionPolicyVersionAction = (
    policyName,
    version,
    newAssertion
) => {
    return addAssertionPolicyVersionToStore(policyName, version, newAssertion);
};
