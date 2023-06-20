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

import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../../actions/loading';
import {
    getExpiryTime,
    getFullName,
    listToMap,
    policyListToMap,
} from '../../utils';
import API from '../../../api';
import { addPolicyToStore, loadPolicies } from '../../actions/policies';
import { policyDelimiter } from '../../config';

export const getPolicyFullName = (domainName, policyName, version) => {
    let fullPolicyName = getFullName(domainName, policyDelimiter, policyName);
    return version ? fullPolicyName + ':' + version : fullPolicyName;
};

export const getPoliciesApiCall = async (domainName, dispatch) => {
    try {
        dispatch(loadingInProcess('getPolicies'));
        const policyList = await API().getPolicies(domainName, true, true);
        const expiry = getExpiryTime();
        dispatch(loadPolicies(policyListToMap(policyList), domainName, expiry));
        dispatch(loadingSuccess('getPolicies'));
    } catch (e) {
        dispatch(loadingFailed('getPolicies'));
        throw e;
    }
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

export const getPolicyApiCall = async (domainName, policyName, dispatch) => {
    try {
        const policy = await API().getPolicy(domainName, policyName);
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

export const buildPolicyDoesntExistErr = (domainName, policyName) => {
    return {
        statusCode: 404,
        body: {
            message: `unknown policy - ${domainName}:policy.${policyName}`,
        },
    };
};

export const buildErrorForPolicyConflict = (domainName, policyName) => {
    return {
        statusCode: 500,
        body: {
            message: `Policy ${policyName} exists in domain ${domainName}`,
        },
    };
};

export const buildPolicyVersionDoesntExistErr = (policyName, version) => {
    return {
        statusCode: 404,
        body: {
            message: `deletepolicyversion: unable to read policy: ${policyName}, version: ${version}`,
        },
    };
};

export const buildAssertionDoesntExistErr = (
    policyName,
    version,
    assertionId
) => {
    return {
        statusCode: 404,
        body: {
            message: `deleteassertionpolicyversion: unable to read assertion: ${assertionId} from policy: ${policyName} version: ${version}`,
        },
    };
};
