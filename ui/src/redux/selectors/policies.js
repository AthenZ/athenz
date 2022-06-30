import { buildPolicyMapKey, mapToList, policyMapToList } from '../utils';

export const thunkSelectPolices = (state) => {
    return state.policies.policies ? state.policies.policies : {};
};

export const selectPolicies = (state) => {
    return state.policies.policies
        ? policyMapToList(state.policies.policies)
        : [];
};

export const selectPolicy = (state, name) => {
    return selectPolicyVersion(state, name, '0');
};

export const selectPolicyVersion = (state, name, version) => {
    let policyMapKey = buildPolicyMapKey(name, version);
    if (state.policies.policies && state.policies.policies[policyMapKey]) {
        const policyVersion = { ...state.policies.policies[policyMapKey] };
        policyVersion.assertions = mapToList(policyVersion.assertions);
        return policyVersion;
    }
    return null;
};
