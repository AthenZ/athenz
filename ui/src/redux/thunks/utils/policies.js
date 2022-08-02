import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import {
    getExpiryTime,
    getFullName,
    listToMap,
    policyListToMap,
} from '../../utils';
import API from '../../../api';
import { addPolicyToStore, loadPolicies } from '../../actions/policies';
import { policyDelimiter } from '../../config';

export const getPolicyFullName = (domainName, policyName) =>
    getFullName(domainName, policyDelimiter, policyName);

export const getPoliciesApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getPolicies'));
    const policyList = await API().getPolicies(domainName, true, true);
    const expiry = getExpiryTime();
    dispatch(loadPolicies(policyListToMap(policyList), domainName, expiry));
    dispatch(loadingSuccess('getPolicies'));
};

export const getPolicyVersionApiCall = async (
    domainName,
    policyName,
    version,
    dispatch
) => {
    try {
        const policyVersion = await API().getPolicyVersion(
            domainName,
            policyName,
            version
        );
        dispatch(
            addPolicyToStore({
                ...policyVersion,
                assertions: listToMap(policyVersion.assertions, 'id'),
            })
        );
        return Promise.resolve(policyVersion);
    } catch (e) {
        throw e;
    }
};

// TODO mendi - remove get policy api call.
export const getPolicyApiCall = async (domainName, policyName, dispatch) => {
    try {
        const policy = await API().getPolicy(domainName, policyName);
        // TODO mendi - change the name of the dispach func to load policy
        dispatch(
            addPolicyToStore({
                ...policy,
                assertions: listToMap(policy.assertions, 'id'),
            })
        );
        return Promise.resolve(policy);
    } catch (e) {
        throw e;
    }
};

export const isPolicyContainsAssertion = (policy, assertionId) => {
    return policy && policy.assertions && !!policy.assertions[assertionId];
};

export const isPolicyContainsAssertionConditions = (policy, assertionId) => {
    return (
        isPolicyContainsAssertion(policy, assertionId) &&
        !!policy.assertions[assertionId].conditions
    );
};

export const isPolicyContainsAssertionCondition = (
    policy,
    assertionId,
    conditionId
) => {
    return (
        isPolicyContainsAssertionConditions(policy, assertionId) &&
        policy.assertions[assertionId].conditions.conditionsList?.some(
            (assertionCondition) => assertionCondition.id === conditionId
        )
    );
};
