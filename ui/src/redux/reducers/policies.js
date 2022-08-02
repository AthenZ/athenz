import {
    ADD_ASSERTION_CONDITIONS,
    ADD_ASSERTION_POLICY_VERSION,
    ADD_POLICY,
    DELETE_ASSERTION_CONDITION,
    DELETE_ASSERTION_CONDITIONS,
    DELETE_ASSERTION_POLICY_VERSION,
    DELETE_POLICY,
    DELETE_POLICY_VERSION,
    DUPLICATE_POLICY_VERSION,
    LOAD_POLICIES,
    MAKE_POLICIES_EXPIRES,
    RETURN_POLICIES,
    SET_ACTIVE_POLICY_VERSION,
} from '../actions/policies';
import { buildPolicyMapKey, getExpiredTime } from '../utils';
import produce from 'immer';

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
                    if (policyKey.startsWith(policyName)) {
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
        // TODO mendi - think about change the policy structure to policyName: { version: {...} }
        case SET_ACTIVE_POLICY_VERSION: {
            const { policyName, version } = payload;
            const newState = produce(state, (draft) => {
                for (let key in draft.policies) {
                    // find the current active version and set it to false
                    if (
                        key.startsWith(policyName) &&
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
        case RETURN_POLICIES:
        default:
            return state;
    }
};
