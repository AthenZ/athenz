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

import { buildPolicyMapKey, mapToList } from '../utils';
import { getPolicyFullName } from '../thunks/utils/policies';

export const selectPoliciesThunk = (state) => {
    return state.policies.policies ? state.policies.policies : {};
};

export const selectPolicies = (state) => {
    return mapToList(selectPoliciesThunk(state));
};

export const selectActivePoliciesOnly = (state) => {
    const allPolicies = selectPolicies(state);
    return allPolicies.filter((policy) => policy.active);
};

export const selectPolicy = (state, domainName, policyName, version) => {
    let policy = selectPolicyThunk(state, domainName, policyName, version);
    return policy && policy.assertions
        ? { ...policy, assertions: mapToList(policy.assertions) }
        : policy;
};

export const selectPolicyTags = (state, domainName, policyName, version) => {
    let policy = selectPolicy(state, domainName, policyName, version);
    return policy && policy.tags ? policy.tags : [];
};

export const selectPolicyThunk = (state, domainName, policyName, version) => {
    const policies = selectPolicies(state);
    const policyFullName = getPolicyFullName(domainName, policyName);
    for (const policy of policies) {
        if (policy.name === policyFullName) {
            if (version) {
                if (policy.version === version) return policy;
            } else if (policy.active) {
                return policy;
            }
        }
    }
    return null;
};

export const selectPolicyAssertions = (state, domainName, policyName) => {
    const policy = selectPolicy(state, domainName, policyName);
    return (policy && policy.assertions) || [];
};

export const selectPolicyVersion = (state, domain, name, version) => {
    let policyMapKey = buildPolicyMapKey(
        getPolicyFullName(domain, name),
        version
    );
    const policies = selectPoliciesThunk(state);
    if (policies && policies[policyMapKey]) {
        const policyVersion = { ...policies[policyMapKey] };
        policyVersion.assertions = mapToList(policyVersion.assertions);
        return policyVersion;
    }
    return null;
};

export const selectPolicyVersionThunk = (state, domain, name, version) => {
    let policyMapKey = buildPolicyMapKey(
        getPolicyFullName(domain, name),
        version
    );
    const policies = selectPoliciesThunk(state);
    if (policies && policies[policyMapKey]) {
        return { ...policies[policyMapKey] };
    }
    return null;
};
