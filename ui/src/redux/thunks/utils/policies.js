import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import {
    getExpiryTime,
    getFullName,
    listToMap,
    policyListToMap,
} from '../../utils';
import API from '../../../api';
import {
    addAssertionConditionsToStore,
    addAssertionPolicyVersionToStore,
    addPolicyToStore,
    deleteAssertionConditionFromStore,
    deleteAssertionConditionsFromStore,
    deleteAssertionPolicyVersionFromStore,
    deletePolicyFromStore,
    deletePolicyVersionFromStore,
    loadPolicies,
    setActivePolicyVersionToStore,
} from '../../actions/policies';
import { policyDelimiter } from '../../config';

const getApi = (() => {
    let api;
    return () => {
        if (api) {
            return api;
        }
        api = API();
        return api;
    }
})();

export const getPolicyFullName = (domainName, policyName) =>
    getFullName(domainName, policyDelimiter, policyName);

export const getPoliciesApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getPolicies'));
    const policyList = await getApi().getPolicies(domainName, true, true);
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
        const policyVersion = await getApi().getPolicyVersion(
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

export const getPolicyApiCall = async (domainName, policyName, dispatch) => {
    try {
        const policy = await getApi().getPolicy(domainName, policyName);
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

export const addPolicyApiCall = async (
    domain,
    name,
    role,
    resource,
    action,
    effect,
    caseSensitive,
    _csrf,
    dispatch
) => {
    try {
        await getApi().addPolicy(
            domain,
            name,
            role,
            resource,
            action,
            effect,
            caseSensitive,
            _csrf
        );
        await getPolicyApiCall(domain, name, dispatch);
    } catch (e) {
        throw e;
    }
};

export const deletePolicyApiCall = async (domain, name, _csrf, dispatch) => {
    await getApi()
        .deletePolicy(domain, name, _csrf)
        .then(() => {
            dispatch(deletePolicyFromStore(getPolicyFullName(domain, name)));
        })
        .catch((e) => {
            throw e;
        });
};

export const duplicatePolicyVersionApiCall = async (
    domain,
    duplicatePolicyName,
    duplicateVersionSourceName,
    duplicateVersionName,
    _csrf,
    dispatch
) => {
    try {
        await getApi().duplicatePolicyVersion(
            domain,
            duplicatePolicyName,
            duplicateVersionSourceName,
            duplicateVersionName,
            _csrf
        );

        await getPolicyVersionApiCall(
            domain,
            duplicatePolicyName,
            duplicateVersionName,
            dispatch
        );
    } catch (e) {
        throw e;
    }
};

export const deletePolicyVersionApiCall = async (
    domain,
    policyName,
    deleteVersionName,
    _csrf,
    dispatch
) => {
    try {
        await getApi().deletePolicyVersion(
            domain,
            policyName,
            deleteVersionName,
            _csrf
        );
        dispatch(
            deletePolicyVersionFromStore(
                getPolicyFullName(domain, policyName),
                deleteVersionName
            )
        );
    } catch (e) {
        throw e;
    }
};

export const setActivePolicyVersionApiCall = async (
    domain,
    name,
    version,
    _csrf,
    dispatch
) => {
    try {
        await getApi().setActivePolicyVersion(domain, name, version, _csrf);
        dispatch(
            setActivePolicyVersionToStore(
                getPolicyFullName(domain, name),
                version
            )
        );
    } catch (e) {
        throw e;
    }
};

export const deleteAssertionApiCall = async (
    domain,
    name,
    policyVersion,
    deleteAssertionId,
    auditRef,
    _csrf,
    dispatch
) => {
    await getApi()
        .deleteAssertion(domain, name, deleteAssertionId, auditRef, _csrf)
        .then(() => {
            dispatch(
                deleteAssertionPolicyVersionFromStore(
                    getPolicyFullName(domain, name),
                    policyVersion,
                    deleteAssertionId
                )
            );
        })
        .catch((e) => {
            throw e;
        });
};

export const deleteAssertionPolicyVersionApiCall = async (
    domain,
    name,
    version,
    deleteAssertionId,
    auditRef,
    _csrf,
    dispatch
) => {
    await getApi()
        .deleteAssertionPolicyVersion(
            domain,
            name,
            version,
            deleteAssertionId,
            auditRef,
            _csrf
        )
        .then(() => {
            dispatch(
                deleteAssertionPolicyVersionFromStore(
                    getPolicyFullName(domain, name),
                    version,
                    deleteAssertionId
                )
            );
        })
        .catch((e) => {
            throw e;
        });
};

export const addAssertionApiCall = async (
    domain,
    name,
    policyVersion,
    role,
    resource,
    action,
    effect,
    caseSensitive,
    _csrf,
    dispatch
) => {
    try {
        const newAssertion = await getApi().addAssertion(
            domain,
            name,
            role,
            resource,
            action,
            effect,
            caseSensitive,
            _csrf
        );
        dispatch(
            addAssertionPolicyVersionToStore(
                getPolicyFullName(domain, name),
                policyVersion,
                newAssertion
            )
        );
        return Promise.resolve(newAssertion);
    } catch (e) {
        throw e;
    }
};

export const addAssertionPolicyVersionApiCall = async (
    domain,
    name,
    version,
    role,
    resource,
    action,
    effect,
    caseSensitive,
    _csrf,
    dispatch
) => {
    try {
        const newAssertion = await getApi().addAssertionPolicyVersion(
            domain,
            name,
            version,
            role,
            resource,
            action,
            effect,
            caseSensitive,
            _csrf
        );
        dispatch(
            addAssertionPolicyVersionToStore(
                getPolicyFullName(domain, name),
                version,
                newAssertion
            )
        );
        return Promise.resolve(newAssertion);
    } catch (e) {
        throw e;
    }
};

export const addAssertionConditionsApiCall = async (
    domain,
    policyName,
    policyVersion,
    assertionId,
    assertionConditions,
    auditRef,
    _csrf,
    dispatch
) => {
    try {
        const newAssertionConditions = await getApi().addAssertionConditions(
            domain,
            policyName,
            assertionId,
            assertionConditions,
            auditRef,
            _csrf
        );
        dispatch(
            addAssertionConditionsToStore(
                getPolicyFullName(domain, policyName),
                policyVersion,
                assertionId,
                newAssertionConditions.conditionsList
            )
        );
        return Promise.resolve(newAssertionConditions);
    } catch (e) {
        throw e;
    }
};

export const deleteAssertionConditionApiCall = async (
    domain,
    policyName,
    policyVersion,
    assertionId,
    conditionId,
    auditRef,
    _csrf,
    dispatch
) => {
    try {
        await getApi().deleteAssertionCondition(
            domain,
            policyName,
            assertionId,
            conditionId,
            auditRef,
            _csrf,
            dispatch
        );
        dispatch(
            deleteAssertionConditionFromStore(
                getPolicyFullName(domain, policyName),
                policyVersion,
                assertionId,
                conditionId
            )
        );
    } catch (e) {
        throw e;
    }
};

export const deleteAssertionConditionsApiCall = async (
    domain,
    policyName,
    policyVersion,
    assertionId,
    auditRef,
    _csrf,
    dispatch
) => {
    try {
        await getApi().deleteAssertionConditions(
            domain,
            policyName,
            assertionId,
            auditRef,
            _csrf,
            dispatch
        );
        dispatch(
            deleteAssertionConditionsFromStore(
                getPolicyFullName(domain, policyName),
                policyVersion,
                assertionId
            )
        );
    } catch (e) {
        throw e;
    }
};
