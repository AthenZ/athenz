import {
    ADD_ASSERTION_POLICY_VERSION,
    ADD_POLICY,
    DELETE_ASSERTION_POLICY_VERSION,
    DELETE_POLICY,
    DELETE_POLICY_VERSION, DUPLICATE_POLICY_VERSION,
    LOAD_POLICIES,
    RETURN_POLICIES, SET_ACTIVE_POLICY_VERSION,
} from '../actions/policies';
import { buildPolicyMapKey } from '../utils';

export const policies = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_POLICIES: {
            const { policies, domainName, expiry } = payload;
            console.log('in load policies with domainName ', policies, domainName, expiry);
            console.log('json', JSON.stringify(policies, undefined, "    "));
            return { domainName, expiry, policies };
        }
        case DELETE_POLICY: {
            const { policyName } = payload;
            const newState = {...state};

            // need to delete all versions of the policy
            for (let policyKey in newState.policies) {
                if (policyKey.startsWith(policyName)) {
                    delete newState.policies[policyKey];
                }
            }
            return newState;
        }
        case DELETE_POLICY_VERSION: {
            const { policyName, deletedVersion } = payload;
            const newState = {...state};
            delete newState.policies[buildPolicyMapKey(policyName, deletedVersion)];
            return newState;
        }
        case ADD_POLICY: {
            const { newPolicy } = payload;
            const { name, version } = newPolicy;
            return {...state,policies: {...state.policies, [buildPolicyMapKey(name, version)]: newPolicy}}
        }
        case DUPLICATE_POLICY_VERSION: {
            const { newDuplicatePolicy } = payload;
            const { name, version } = newDuplicatePolicy;
            return {...state, policies: {...state.policies, [buildPolicyMapKey(name, version)]: newDuplicatePolicy}}
        }
        case SET_ACTIVE_POLICY_VERSION: {
            const { policyName, version } = payload;
            const newState = {...state};
            // find the current active version and set it to false
            for (let key in newState.policies) {
                if (key.startsWith(policyName) && newState.policies[key].active) {
                    newState.policies[key].active = false;
                    break;
                }
            }
            // set  the new active version true
            newState.policies[buildPolicyMapKey(policyName, version)].active = true;
            return newState;
        }
        case ADD_ASSERTION_POLICY_VERSION: {
            const { policyName, version, newAssertion } = payload;
            const newState = {...state};
            let key = buildPolicyMapKey(policyName, version);
            newState[key].assertions[newAssertion['id']] = newAssertion;
            return newState;
        }
        case DELETE_ASSERTION_POLICY_VERSION: {
            const { policyName, version, assertionId } = payload
            console.log("############state", state);
            const newState = {...state};
            console.log("############newState",  newState.policies[buildPolicyMapKey(policyName, version)].assertions);
            delete newState.policies[buildPolicyMapKey(policyName, version)].assertions[assertionId];
            return newState;
        }
        case RETURN_POLICIES:
            return state;
        default:
            return state;
    }
};
