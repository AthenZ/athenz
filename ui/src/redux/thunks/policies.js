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

import { storePolicies } from '../actions/domains';
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
    returnPolicies,
    setActivePolicyVersionToStore,
} from '../actions/policies';
import {
    buildErrorForPolicyConflict,
    buildPolicyDoesntExistErr,
    buildPolicyVersionDoesntExistErr,
    getPoliciesApiCall,
    getPolicyApiCall,
    getPolicyFullName,
    getPolicyVersionApiCall,
    isPolicyContainsAssertion,
    isPolicyContainsAssertionCondition,
    isPolicyContainsAssertionConditions,
} from './utils/policies';
import {
    selectPoliciesThunk,
    selectPolicy,
    selectPolicyThunk,
    selectPolicyVersion,
    selectPolicyVersionThunk,
} from '../selectors/policies';
import reduxApiUtils from '../../server/utils/reduxApiUtils';
import {
    buildErrorForDoesntExistCase,
    buildPolicyMapKey,
    isExpired,
    listToMap,
} from '../utils';
import API from '../../api';

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
                        getState().domains[domainName].policies.policies,
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
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const addPolicy =
    (domain, name, role, resource, action, effect, caseSensitive, _csrf) =>
    async (dispatch, getState) => {
        name = name.toLowerCase();
        await dispatch(getPolicies(domain));
        try {
            let policies = selectPoliciesThunk(getState());
            if (
                policies[
                    buildPolicyMapKey(getPolicyFullName(domain, name), '0')
                ]
            ) {
                return Promise.reject(
                    buildErrorForPolicyConflict(domain, name)
                );
            } else {
                let addedPolicy = await API().addPolicy(
                    domain,
                    name,
                    role,
                    resource,
                    action,
                    effect,
                    caseSensitive,
                    _csrf,
                    true
                );
                dispatch(
                    addPolicyToStore({
                        ...addedPolicy,
                        assertions: listToMap(addedPolicy.assertions, 'id'),
                    })
                );
                return Promise.resolve();
            }
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const deletePolicy =
    (domain, name, _csrf) => async (dispatch, getState) => {
        name = name.toLowerCase();
        await dispatch(getPolicies(domain));
        const policyToDelete = selectPolicyThunk(getState(), domain, name);
        if (policyToDelete) {
            try {
                await API().deletePolicy(domain, name, _csrf);
                dispatch(
                    deletePolicyFromStore(getPolicyFullName(domain, name))
                );
                return Promise.resolve();
            } catch (e) {
                return Promise.reject(e);
            }
        } else {
            return Promise.reject(buildPolicyDoesntExistErr(domain, name));
        }
    };

export const deletePolicyVersion =
    (domain, policyName, deleteVersionName, _csrf) =>
    async (dispatch, getState) => {
        policyName = policyName.toLowerCase();
        await dispatch(getPolicies(domain));
        const versionToDelete = selectPolicyVersionThunk(
            getState(),
            domain,
            policyName,
            deleteVersionName
        );
        if (versionToDelete) {
            try {
                await API().deletePolicyVersion(
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
                return Promise.resolve();
            } catch (e) {
                return Promise.reject(e);
            }
        } else {
            return Promise.reject(
                buildPolicyVersionDoesntExistErr(policyName, deleteVersionName)
            );
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
            duplicatePolicyName = duplicatePolicyName.toLowerCase();
            let duplicatedPolicyVersion = await API().duplicatePolicyVersion(
                domain,
                duplicatePolicyName,
                duplicateVersionSourceName,
                duplicateVersionName,
                _csrf,
                true
            );

            dispatch(
                addPolicyToStore({
                    ...duplicatedPolicyVersion,
                    assertions: listToMap(
                        duplicatedPolicyVersion.assertions,
                        'id'
                    ),
                })
            );

            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const setActivePolicyVersion =
    (domain, name, version, _csrf) => async (dispatch, getState) => {
        try {
            name = name.toLowerCase();
            await API().setActivePolicyVersion(domain, name, version, _csrf);
            dispatch(
                setActivePolicyVersionToStore(
                    getPolicyFullName(domain, name),
                    version
                )
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const deleteAssertion =
    (domain, name, deleteAssertionId, auditRef, _csrf) =>
    async (dispatch, getState) => {
        name = name.toLowerCase();
        await dispatch(getPolicies(domain));
        const policy = selectPolicyThunk(getState(), domain, name);
        if (!isPolicyContainsAssertion(policy, deleteAssertionId)) {
            return Promise.reject(buildErrorForDoesntExistCase('Assertion'));
        }
        try {
            await API().deleteAssertion(
                domain,
                name,
                deleteAssertionId,
                auditRef,
                _csrf
            );
            dispatch(
                deleteAssertionPolicyVersionFromStore(
                    getPolicyFullName(domain, name),
                    policy.version,
                    deleteAssertionId
                )
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const deleteAssertionPolicyVersion =
    (domain, name, version, deleteAssertionId, auditRef, _csrf) =>
    async (dispatch, getState) => {
        name = name.toLowerCase();
        await dispatch(getPolicies(domain));
        const policyVersion = selectPolicyVersionThunk(
            getState(),
            domain,
            name,
            version
        );
        if (!isPolicyContainsAssertion(policyVersion, deleteAssertionId)) {
            return Promise.reject(buildErrorForDoesntExistCase('Assertion'));
        }
        try {
            await API().deleteAssertionPolicyVersion(
                domain,
                name,
                version,
                deleteAssertionId,
                auditRef,
                _csrf
            );
            dispatch(
                deleteAssertionPolicyVersionFromStore(
                    getPolicyFullName(domain, name),
                    version,
                    deleteAssertionId
                )
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const addAssertion =
    (domain, name, role, resource, action, effect, caseSensitive, _csrf) =>
    async (dispatch, getState) => {
        name = name.toLowerCase();
        await dispatch(getPolicies(domain));
        const policy = selectPolicyThunk(getState(), domain, name);
        if (!policy) {
            return Promise.reject(buildPolicyDoesntExistErr(domain, name));
        }
        try {
            const newAssertion = await API().addAssertion(
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
                    policy.version,
                    newAssertion
                )
            );
            return Promise.resolve(newAssertion);
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
        name = name.toLowerCase();
        await dispatch(getPolicies(domain));
        const policyVersion = selectPolicyVersionThunk(
            getState(),
            domain,
            name,
            version
        );
        if (!policyVersion) {
            return Promise.reject(
                buildPolicyVersionDoesntExistErr(name, version)
            );
        }
        try {
            const newAssertion = await API().addAssertionPolicyVersion(
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
            return Promise.reject(e);
        }
    };

export const addAssertionConditions =
    (domain, policyName, assertionId, assertionConditions, auditRef, _csrf) =>
    async (dispatch, getState) => {
        policyName = policyName.toLowerCase();
        await dispatch(getPolicies(domain));
        const policy = selectPolicyThunk(getState(), domain, policyName);
        if (!isPolicyContainsAssertion(policy, assertionId)) {
            return Promise.reject(buildErrorForDoesntExistCase('Assertion'));
        }
        try {
            const newAssertionConditions = await API().addAssertionConditions(
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
                    policy.version,
                    assertionId,
                    newAssertionConditions.conditionsList
                )
            );
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const deleteAssertionCondition =
    (domain, policyName, assertionId, conditionId, auditRef, _csrf) =>
    async (dispatch, getState) => {
        policyName = policyName.toLowerCase();
        await dispatch(getPolicies(domain));
        const policy = selectPolicyThunk(getState(), domain, policyName);
        if (
            !isPolicyContainsAssertionCondition(
                policy,
                assertionId,
                conditionId
            )
        ) {
            return Promise.reject(
                buildErrorForDoesntExistCase('Assertion Condition')
            );
        }
        try {
            await API().deleteAssertionCondition(
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
                    policy.version,
                    assertionId,
                    conditionId
                )
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const deleteAssertionConditions =
    (domain, policyName, assertionId, auditRef, _csrf) =>
    async (dispatch, getState) => {
        policyName = policyName.toLowerCase();
        await dispatch(getPolicies(domain));
        const policy = selectPolicyThunk(getState(), domain, policyName);
        if (!isPolicyContainsAssertionConditions(policy, assertionId)) {
            return Promise.reject(
                buildErrorForDoesntExistCase('Assertion Conditions')
            );
        }
        try {
            await API().deleteAssertionConditions(
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
                    policy.version,
                    assertionId
                )
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const getAssertionId =
    (domainName, policyName, role, resource, action, effect) =>
    async (dispatch, getState) => {
        policyName = policyName.toLowerCase();
        await dispatch(getPolicies(domainName, policyName));
        const policy = selectPolicy(getState(), domainName, policyName);
        if (!policy) {
            const err = buildPolicyDoesntExistErr(domainName, policyName);
            return Promise.reject(err);
        }
        const assertionId = reduxApiUtils.extractAssertionId(
            policy,
            domainName,
            role,
            action,
            effect,
            resource
        );
        if (assertionId === -1) {
            const err = buildErrorForDoesntExistCase('Assertion');
            return Promise.reject(err);
        }
        return Promise.resolve(assertionId);
    };
