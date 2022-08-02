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

export const selectPolicy = (state, domainName, policyName) => {
    const allActivePolicyVersion = selectActivePoliciesOnly(state);
    const policyFullName = getPolicyFullName(domainName, policyName);
    for (const policy of allActivePolicyVersion) {
        if (policy.name === policyFullName) {
            return { ...policy, assertions: mapToList(policy.assertions) };
        }
    }
    return null;
};

export const selectPolicyThunk = (state, domainName, policyName) => {
    const allActivePolicyVersion = selectActivePoliciesOnly(state);
    const policyFullName = getPolicyFullName(domainName, policyName);
    for (const policy of allActivePolicyVersion) {
        if (policy.name === policyFullName) {
            return policy;
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
