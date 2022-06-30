import API from '../../api';
import { storePolicies } from '../actions/domains';
import {
    loadPolicies,
    returnPolicies,
    deletePolicyFromStore,
    addPolicyToStore,
    deletePolicyVersionFromStore,
    deleteAssertionPolicyVersionFromState,
    addAssertionPolicyVersionToStore,
    duplicatePolicyVersionToStore,
    setActivePolicyVersionToStore,
} from '../actions/policies';
import { getPoliciesApiCall } from './utils/policies';
import { buildPolicyMapKey } from '../utils';

// TODO make an error reducer
const api = API();

const getFullName = (domain, name) => domain + ':policy.' + name;

export const getPolicies =
    (domainName, assertions, includeNonActive) =>
    async (dispatch, getState) => {
        if (getState().policies.expiry) {
            if (getState().policies.domainName !== domainName) {
                dispatch(storePolicies(getState().policies));
                if (
                    getState().domains[domainName] &&
                    getState().domains[domainName].policies &&
                    getState().domains[domainName].policies.expiry > 0
                ) {
                    dispatch(
                        loadPolicies(
                            getState().domains[domainName].policies,
                            domainName,
                            getState().domains[domainName].policies.expiry
                        )
                    );
                } else {
                    await getPoliciesApiCall(
                        domainName,
                        assertions,
                        includeNonActive,
                        dispatch
                    );
                }
            } else if (getState().policies.expiry <= 0) {
                await getPoliciesApiCall(
                    domainName,
                    assertions,
                    includeNonActive,
                    dispatch
                );
            } else {
                dispatch(returnPolicies());
            }
        } else {
            await getPoliciesApiCall(
                domainName,
                assertions,
                includeNonActive,
                dispatch
            );
        }
    };

export const getPolicyVersion =
    (domain, name, version, onSuccess, onFail) =>
    async (dispatch, getState) => {
        await dispatch(getPolicies(domain, true, true));
        const policyVersion = getState().policies.policies[buildPolicyMapKey(name,version)];
        if (policyVersion) {
            onSuccess(policyVersion);
        } else {
            // try to retrieve from the server
            await api
                .getPolicyVersion(domain, name, version)
                .then((policyVersion) => {
                    dispatch(addPolicyToStore(policyVersion));
                    onSuccess(policyVersion);
                })
                .catch((e) => {
                    onFail(e);
                });
        }
    };

export const addPolicy =
    (
        domain,
        name,
        role,
        resource,
        action,
        effect,
        caseSensitive,
        _csrf,
        onSuccess,
        onFail
    ) =>
    async (dispatch, getState) => {
        await api
            .addPolicy(
                domain,
                name,
                role,
                resource,
                action,
                effect,
                caseSensitive,
                _csrf
            )
            .then(() => {
                dispatch(
                    getPolicyVersion(
                        domain,
                        name,
                        '0',
                        (mewPolicy) =>
                            console.log(
                                'about to addPolicyToStore, new policy:',
                                mewPolicy
                            ),
                        onFail
                    )
                );
                onSuccess();
            })
            .catch((e) => {
                onFail(e);
            });
    };

export const deletePolicy =
    (domain, name, _csrf, onSuccess, onFail) => async (dispatch, getState) => {
        await api
            .deletePolicy(domain, name, _csrf)
            .then(() => {
                dispatch(deletePolicyFromStore(name));
                onSuccess();
            })
            .catch((e) => {
                onFail(e);
            });
    };

export const duplicatePolicyVersion =
    (
        domain,
        duplicatePolicyName,
        duplicateVersionSourceName,
        duplicateVersionName,
        _csrf,
        resolve,
        reject
    ) =>
    async (dispatch, getState) => {
        console.log('duplicateVersionSourceName', duplicateVersionSourceName);
        const onSuccess = async (sourceVersion) => {
            await api
                .duplicatePolicyVersion(
                    domain,
                    duplicatePolicyName,
                    duplicateVersionSourceName,
                    duplicateVersionName,
                    _csrf
                )
                .then(() => {
                    const duplicateVersion = {
                        ...sourceVersion,
                        active: false,
                        version: duplicateVersionName,
                    };
                    dispatch(duplicatePolicyVersionToStore(duplicateVersion));
                    resolve();
                })
                .catch((e) => {
                    reject(e);
                });
        };
        // const onFail = (err) => {
        // }
        dispatch(
            getPolicyVersion(
                domain,
                duplicatePolicyName,
                duplicateVersionSourceName,
                onSuccess,
                reject
            )
        );
    };

export const setActivePolicyVersion =
    (domain, name, version, _csrf, onSuccess, onFail) =>
    async (dispatch, getState) => {
        await api
            .setActivePolicyVersion(domain, name, version, _csrf)
            .then(() => {
                dispatch(
                    setActivePolicyVersionToStore(
                        name,
                        version
                    )
                );
                onSuccess();
            })
            .catch((e) => {
                onFail(e);
            });
    };
export const deletePolicyVersion =
    (domain, policyName, deleteVersionName, _csrf, onSuccess, onFail) =>
    async (dispatch, getState) => {
        await api
            .deletePolicyVersion(domain, policyName, deleteVersionName, _csrf)
            .then(() => {
                dispatch(
                    deletePolicyVersionFromStore(
                        domain,
                        policyName,
                        deleteVersionName
                    )
                );
                onSuccess();
            })
            .catch((e) => {
                onFail(e);
            });
    };

export const deleteAssertionPolicyVersion =
    (
        domain,
        name,
        version,
        deleteAssertionId,
        auditRef,
        _csrf,
        onSuccess,
        onFail
    ) =>
    async (dispatch, getState) => {
        await api
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
                    deleteAssertionPolicyVersionFromState(
                        name,
                        version,
                        deleteAssertionId
                    )
                );
                onSuccess();
            })
            .catch((e) => {
                onFail(e);
            });
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
        _csrf,
        onSuccess,
        onFail
    ) =>
    async (dispatch, getState) => {
        await api
            .addAssertionPolicyVersion(
                domain,
                name,
                version,
                role,
                resource,
                action,
                effect,
                caseSensitive,
                _csrf
            )
            .then((assertion) => {
                dispatch(
                    addAssertionPolicyVersionToStore(
                        name,
                        version,
                        assertion
                    )
                );
                onSuccess(assertion);
            })
            .catch((e) => {
                onFail(e);
            });
    };
