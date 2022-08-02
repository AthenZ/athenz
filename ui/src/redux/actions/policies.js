export const LOAD_POLICIES = 'LOAD_POLICIES';
export const loadPolicies = (policies, domainName, expiry) => ({
    type: LOAD_POLICIES,
    payload: { policies: policies, domainName: domainName, expiry: expiry },
});

export const RETURN_POLICIES = 'RETURN_POLICIES';
export const returnPolicies = () => ({
    type: RETURN_POLICIES,
});

export const DELETE_POLICY = 'DELETE_POLICY';
export const deletePolicyFromStore = (policyName) => ({
    type: DELETE_POLICY,
    payload: { policyName: policyName },
});

export const DELETE_POLICY_VERSION = 'DELETE_POLICY_VERSION';
export const deletePolicyVersionFromStore = (policyName, deletedVersion) => ({
    type: DELETE_POLICY_VERSION,
    payload: { policyName, deletedVersion },
});

export const ADD_POLICY = 'ADD_POLICY';
export const addPolicyToStore = (newPolicy) => ({
    type: ADD_POLICY,
    payload: { newPolicy },
});

export const SET_ACTIVE_POLICY_VERSION = 'SET_ACTIVE_POLICY_VERSION';
export const setActivePolicyVersionToStore = (policyName, version) => ({
    type: SET_ACTIVE_POLICY_VERSION,
    payload: { policyName, version },
});

export const ADD_ASSERTION_POLICY_VERSION = 'ADD_ASSERTION_POLICY_VERSION';
export const addAssertionPolicyVersionToStore = (
    policyName,
    version,
    newAssertion
) => ({
    type: ADD_ASSERTION_POLICY_VERSION,
    payload: {
        policyName,
        version,
        newAssertion,
    },
});

export const DELETE_ASSERTION_POLICY_VERSION =
    'DELETE_ASSERTION_POLICY_VERSION';
export const deleteAssertionPolicyVersionFromStore = (
    policyName,
    version,
    assertionId
) => ({
    type: DELETE_ASSERTION_POLICY_VERSION,
    payload: { policyName, version, assertionId },
});

export const ADD_ASSERTION_CONDITIONS = 'ADD_ASSERTION_CONDITIONS';
export const addAssertionConditionsToStore = (
    policyName,
    version,
    assertionId,
    conditionsList
) => ({
    type: ADD_ASSERTION_CONDITIONS,
    payload: { policyName, version, assertionId, conditionsList },
});

export const DELETE_ASSERTION_CONDITION = 'DELETE_ASSERTION_CONDITION';
export const deleteAssertionConditionFromStore = (
    policyName,
    version,
    assertionId,
    conditionId
) => ({
    type: DELETE_ASSERTION_CONDITION,
    payload: { policyName, version, assertionId, conditionId },
});

export const DELETE_ASSERTION_CONDITIONS = 'DELETE_ASSERTION_CONDITIONS';
export const deleteAssertionConditionsFromStore = (
    policyName,
    version,
    assertionId
) => ({
    type: DELETE_ASSERTION_CONDITIONS,
    payload: { policyName, version, assertionId },
});

export const MAKE_POLICIES_EXPIRES = 'MAKE_POLICIES_EXPIRES';
export const makePoliciesExpires = () => ({
    type: MAKE_POLICIES_EXPIRES,
});
