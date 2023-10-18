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
    ADD_ASSERTION_CONDITIONS,
    ADD_ASSERTION_POLICY_VERSION,
    ADD_POLICY,
    DELETE_ASSERTION_CONDITION,
    DELETE_ASSERTION_CONDITIONS,
    DELETE_ASSERTION_POLICY_VERSION,
    DELETE_POLICY,
    DELETE_POLICY_VERSION,
    LOAD_POLICIES,
    MAKE_POLICIES_EXPIRES,
    RETURN_POLICIES,
    SET_ACTIVE_POLICY_VERSION,
} from '../actions/policies';
import { buildPolicyMapKey, getExpiredTime } from '../utils';
import produce from 'immer';
import { UPDATE_TAGS_TO_STORE } from '../actions/collections';

export const policies = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_POLICIES: {
            const { policies, domainName, expiry } = payload;
            return { domainName, expiry, policies };
        }
        case DELETE_POLICY: {
            const { policyName } = payload;
            const newState = produce(state, (draft) => {
                // need to delete all versions of the policy
                for (let policyKey in draft.policies) {
                    if (policyKey.startsWith(policyName + ':')) {
                        delete draft.policies[policyKey];
                    }
                }
            });
            return newState;
        }
        case DELETE_POLICY_VERSION: {
            const { policyName, deletedVersion } = payload;
            const newState = produce(state, (draft) => {
                delete draft.policies[
                    buildPolicyMapKey(policyName, deletedVersion)
                ];
            });
            return newState;
        }
        case ADD_POLICY: {
            const { newPolicy } = payload;
            const { name, version } = newPolicy;
            const newState = produce(state, (draft) => {
                draft.policies[buildPolicyMapKey(name, version)] = newPolicy;
            });
            return newState;
        }

        case SET_ACTIVE_POLICY_VERSION: {
            const { policyName, version } = payload;
            const newState = produce(state, (draft) => {
                for (let key in draft.policies) {
                    // find the current active version and set it to false
                    if (
                        key.startsWith(policyName + ':') &&
                        draft.policies[key].active
                    ) {
                        draft.policies[key].active = false;
                        break;
                    }
                }

                // set the new active version true
                draft.policies[
                    buildPolicyMapKey(policyName, version)
                ].active = true;
            });
            return newState;
        }
        case ADD_ASSERTION_POLICY_VERSION: {
            const { policyName, version, newAssertion } = payload;
            const newState = produce(state, (draft) => {
                let key = buildPolicyMapKey(policyName, version);
                draft.policies[key].assertions[newAssertion['id']] =
                    newAssertion;
            });
            return newState;
        }
        case DELETE_ASSERTION_POLICY_VERSION: {
            const { policyName, version, assertionId } = payload;
            const newState = produce(state, (draft) => {
                delete draft.policies[buildPolicyMapKey(policyName, version)]
                    .assertions[assertionId];
            });
            return newState;
        }
        case ADD_ASSERTION_CONDITIONS: {
            const { policyName, version, assertionId, conditionsList } =
                payload;
            const key = buildPolicyMapKey(policyName, version);
            const newState = produce(state, (draft) => {
                if (
                    draft.policies[key].assertions[assertionId].conditions
                        ?.conditionsList
                ) {
                    draft.policies[key].assertions[
                        assertionId
                    ].conditions.conditionsList =
                        draft.policies[key].assertions[
                            assertionId
                        ].conditions.conditionsList.concat(conditionsList);
                } else {
                    draft.policies[key].assertions[assertionId].conditions = {
                        conditionsList,
                    };
                }
            });
            return newState;
        }
        case DELETE_ASSERTION_CONDITION: {
            const { policyName, version, assertionId, conditionId } = payload;
            const key = buildPolicyMapKey(policyName, version);
            const newState = produce(state, (draft) => {
                draft.policies[key].assertions[
                    assertionId
                ].conditions.conditionsList = draft.policies[key].assertions[
                    assertionId
                ].conditions.conditionsList.filter(
                    (condition) => condition.id !== conditionId
                );
            });
            return newState;
        }
        case DELETE_ASSERTION_CONDITIONS: {
            const { policyName, version, assertionId } = payload;
            const key = buildPolicyMapKey(policyName, version);
            const newState = produce(state, (draft) => {
                delete draft.policies[key].assertions[assertionId].conditions;
            });
            return newState;
        }
        case MAKE_POLICIES_EXPIRES: {
            return produce(state, (draft) => {
                draft.expiry = getExpiredTime();
            });
        }
        case UPDATE_TAGS_TO_STORE: {
            const { collectionName, collectionWithTags, category } = payload;
            let newState = state;
            if (category === 'policy') {
                let collectionNameWithVersion =
                    collectionName + ':' + collectionWithTags.version;
                newState = produce(state, (draft) => {
                    draft.policies[collectionNameWithVersion]
                        ? (draft.policies[collectionNameWithVersion].tags =
                              collectionWithTags.tags)
                        : (draft.policies[collectionNameWithVersion] =
                              collectionWithTags);
                });
            }
            return newState;
        }
        case RETURN_POLICIES:
        default:
            return state;
    }
};
