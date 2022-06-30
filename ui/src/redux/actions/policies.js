export const LOAD_POLICIES = 'LOAD_POLICIES';
export const loadPolicies = (policies, domainName, expiry) => ({
    type: LOAD_POLICIES,
    payload: { policies: policies, domainName: domainName, expiry: expiry },
});

export const RETURN_POLICIES = 'RETURN_POLICIES';
export const returnPolicies = () => ({
    type: RETURN_POLICIES,
});

export const DELETE_POLICY = "DELETE_POLICY";
export const deletePolicyFromStore = (policyName) => ({
    type: DELETE_POLICY,
    payload: { policyName: policyName }
});

export const DELETE_POLICY_VERSION = "DELETE_POLICY_VERSION";
export const deletePolicyVersionFromStore = (domainName, policyName, deletedVersion) => ({
    type: DELETE_POLICY_VERSION,
    payload: { policyName: policyName, deletedVersion: deletedVersion }
});

export const ADD_POLICY = 'ADD_POLICY';
export const addPolicyToStore = (newPolicy) => ({
    type: ADD_POLICY,
    payload: { newPolicy: newPolicy }
});

export const DUPLICATE_POLICY_VERSION = 'DUPLICATE_POLICY_VERSION';
export const duplicatePolicyVersionToStore = (newDuplicatePolicy) => ({
    type: DUPLICATE_POLICY_VERSION,
    payload: { newDuplicatePolicy: newDuplicatePolicy }
});

export const SET_ACTIVE_POLICY_VERSION = 'SET_ACTIVE_POLICY_VERSION';
export const setActivePolicyVersionToStore = (policyName, version) => ({
    type: SET_ACTIVE_POLICY_VERSION,
    payload: { policyName: policyName, version:version}
});

export const ADD_ASSERTION_POLICY_VERSION = 'ADD_ASSERTION_POLICY_VERSION';
export const addAssertionPolicyVersionToStore = (policyName, version, newAssertion) => ({
    type: ADD_ASSERTION_POLICY_VERSION,
    payload: { policyFullName: policyName, version:version, newAssertion: newAssertion}
});

export const DELETE_ASSERTION_POLICY_VERSION = 'DELETE_ASSERTION_POLICY_VERSION';
export const deleteAssertionPolicyVersionFromState = (policyName, version, assertionId) => ({
   type: DELETE_ASSERTION_POLICY_VERSION,
    payload: { policyName: policyName, version: version, assertionId: assertionId }
});
