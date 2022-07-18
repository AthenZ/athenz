import { storePolicies } from '../actions/domains';
import { loadPolicies, returnPolicies } from '../actions/policies';
import {
    addAssertionApiCall,
    addAssertionConditionsApiCall,
    addAssertionPolicyVersionApiCall,
    addPolicyApiCall,
    deleteAssertionApiCall,
    deleteAssertionConditionApiCall,
    deleteAssertionConditionsApiCall,
    deleteAssertionPolicyVersionApiCall,
    deletePolicyApiCall,
    deletePolicyVersionApiCall,
    duplicatePolicyVersionApiCall,
    getPoliciesApiCall,
    getPolicyApiCall,
    getPolicyFullName,
    getPolicyVersionApiCall,
    setActivePolicyVersionApiCall,
} from './utils/policies';
import {
    selectPolicesThunk,
    selectPolicy,
    selectPolicyVersion,
} from '../selectors/policies';
import apiUtils from '../../server/utils/apiUtils';
import { isExpired } from '../utils';

export const getPolicies = (domainName) => async (dispatch, getState) => {
    if (getState().policies.expiry) {
        if (getState().policies.domainName !== domainName) {
            dispatch(storePolicies(getState().policies));
            if (
                getState().domains[domainName] &&
                getState().domains[domainName].policies &&
                !isExpired(getState().domains[domainName].policies.expiry)
            ) {
                dispatch(
                    loadPolicies(
                        getState().domains[domainName].policies,
                        domainName,
                        getState().domains[domainName].policies.expiry
                    )
                );
            } else {
                await getPoliciesApiCall(domainName, dispatch);
            }
        } else if (isExpired(getState().policies.expiry)) {
            await getPoliciesApiCall(domainName, dispatch);
        } else {
            dispatch(returnPolicies());
        }
    } else {
        await getPoliciesApiCall(domainName, dispatch);
    }
};

export const getPolicy = (domain, name) => async (dispatch, getState) => {
    await dispatch(getPolicies(domain));
    const policy = selectPolicy(getState(), domain, name);
    if (policy) {
        return Promise.resolve(policy);
    }
    try {
        const policy = await getPolicyApiCall(domain, name, dispatch);
        return Promise.resolve(policy);
    } catch (e) {
        return Promise.reject(e);
    }
};

export const getPolicyVersion =
    (domain, name, version) => async (dispatch, getState) => {
        await dispatch(getPolicies(domain));
        const policyVersion = selectPolicyVersion(
            getState(),
            domain,
            name,
            version
        );
        if (policyVersion) {
            return Promise.resolve(policyVersion);
        }
        // try to retrieve from the server
        try {
            return await getPolicyVersionApiCall(
                domain,
                name,
                version,
                dispatch
            );
            // Promise.resolve(newPolicyVersion);
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const addPolicy =
    (domain, name, role, resource, action, effect, caseSensitive, _csrf) =>
    async (dispatch, getState) => {
        await dispatch(getPolicies(domain));
        try {
            let policies = selectPolicesThunk(getState());
            if (policies[getPolicyFullName(domain, name) + ':0']) {
                return Promise.reject({
                    body: { message: 'Policy version already exists' },
                    statusCode: 500,
                });
            } else {
                await addPolicyApiCall(
                    domain,
                    name,
                    role,
                    resource,
                    action,
                    effect,
                    caseSensitive,
                    _csrf,
                    dispatch
                );
                return Promise.resolve();
            }
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const deletePolicy =
    (domain, name, _csrf) => async (dispatch, getState) => {
        await dispatch(getPolicies(domain));
        const policyToDelete = selectPolicy(getState(), domain, name);
        if (policyToDelete) {
            try {
                await deletePolicyApiCall(domain, name, _csrf, dispatch);
                return Promise.resolve();
            } catch (e) {
                return Promise.reject(e);
            }
        } else {
            return Promise.reject({
                body: { message: 'Policy does not exists' },
                statusCode: 400,
            });
        }
    };

export const deletePolicyVersion =
    (domain, policyName, deleteVersionName, _csrf) =>
    async (dispatch, getState) => {
        const versionToDelete = selectPolicyVersion(
            getState(),
            domain,
            policyName,
            deleteVersionName
        );
        if (versionToDelete) {
            try {
                await deletePolicyVersionApiCall(
                    domain,
                    policyName,
                    deleteVersionName,
                    _csrf,
                    dispatch
                );
                return Promise.resolve();
            } catch (e) {
                return Promise.reject(e);
            }
        } else {
            return Promise.reject({
                body: { message: 'Policy version does not exists' },
                statusCode: 400,
            });
        }
    };

export const duplicatePolicyVersion =
    (
        domain,
        duplicatePolicyName,
        duplicateVersionSourceName,
        duplicateVersionName,
        _csrf
    ) =>
    async (dispatch, getState) => {
        try {
            await duplicatePolicyVersionApiCall(
                domain,
                duplicatePolicyName,
                duplicateVersionSourceName,
                duplicateVersionName,
                _csrf,
                dispatch
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const setActivePolicyVersion =
    (domain, name, version, _csrf) => async (dispatch, getState) => {
        try {
            await setActivePolicyVersionApiCall(
                domain,
                name,
                version,
                _csrf,
                dispatch
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const deleteAssertion =
    (domain, name, deleteAssertionId, auditRef, _csrf) =>
    async (dispatch, getState) => {
        await dispatch(getPolicies(domain));
        const policy = selectPolicy(getState(), domain, name);
        if (!policy) {
            //TODO - throw error
            return Promise.reject();
        }
        try {
            await deleteAssertionApiCall(
                domain,
                name,
                policy.version,
                deleteAssertionId,
                auditRef,
                _csrf,
                dispatch
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const deleteAssertionPolicyVersion =
    (domain, name, version, deleteAssertionId, auditRef, _csrf) =>
    async (dispatch, getState) => {
        try {
            await deleteAssertionPolicyVersionApiCall(
                domain,
                name,
                version,
                deleteAssertionId,
                auditRef,
                _csrf,
                dispatch
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const addAssertion =
    (domain, name, role, resource, action, effect, caseSensitive, _csrf) =>
    async (dispatch, getState) => {
        await dispatch(getPolicies(domain));
        const policy = selectPolicy(getState(), domain, name);
        if (!policy) {
            //TODO - throw error
            return Promise.reject();
        }
        try {
            return await addAssertionApiCall(
                domain,
                name,
                policy.version,
                role,
                resource,
                action,
                effect,
                caseSensitive,
                _csrf,
                dispatch
            );
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const addAssertionPolicyVersion =
    (
        domain,
        name,
        version,
        role,
        resource,
        action,
        effect,
        caseSensitive,
        _csrf
    ) =>
    async (dispatch, getState) => {
        try {
            return await addAssertionPolicyVersionApiCall(
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
            );
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const addAssertionConditions =
    (domain, policyName, assertionId, assertionConditions, auditRef, _csrf) =>
    async (dispatch, getState) => {
        await dispatch(getPolicies(domain));
        const policy = selectPolicy(getState(), domain, policyName);
        if (!policy) {
            //TODO - throw error
            return Promise.reject();
        }
        try {
            return await addAssertionConditionsApiCall(
                domain,
                policyName,
                policy.version,
                assertionId,
                assertionConditions,
                auditRef,
                _csrf,
                dispatch
            );
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const deleteAssertionCondition =
    (domain, policyName, assertionId, conditionId, auditRef, _csrf) =>
    async (dispatch, getState) => {
        await dispatch(getPolicies(domain));
        const policy = selectPolicy(getState(), domain, policyName);
        if (!policy) {
            //TODO - throw error
            return Promise.reject();
        }
        try {
            await deleteAssertionConditionApiCall(
                domain,
                policyName,
                policy.version,
                assertionId,
                conditionId,
                auditRef,
                _csrf,
                dispatch
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const deleteAssertionConditions =
    (domain, policyName, assertionId, auditRef, _csrf) =>
    async (dispatch, getState) => {
        await dispatch(getPolicies(domain));
        const policy = selectPolicy(getState(), domain, policyName);
        if (!policy) {
            //TODO - throw error
            return Promise.reject();
        }
        try {
            await deleteAssertionConditionsApiCall(
                domain,
                policyName,
                policy.version,
                assertionId,
                auditRef,
                _csrf,
                dispatch
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const getAssertionId =
    (domainName, policyName, role, resource, action, effect) =>
    async (dispatch, getState) => {
        await getPolicy(domainName, policyName);
        const policy = selectPolicy(getState(), domainName, policyName);
        if (!policy) {
            const err = {
                status: 404,
                message: {
                    message: `Failed to get policy ${policyName}.`,
                },
            };
            return Promise.reject(err);
        }
        const assertionId = apiUtils.extractAssertionId(
            policy,
            domainName,
            role,
            action,
            effect,
            resource
        );
        if (assertionId === -1) {
            const err = {
                status: 404,
                message: {
                    message: `Failed to get assertion for policy ${policyName}.`,
                },
            };
            return Promise.reject(err);
        }
        return Promise.resolve(assertionId);
    };
