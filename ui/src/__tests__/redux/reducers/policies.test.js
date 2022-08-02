import { _ } from 'lodash';
import {
    apiAssertionConditions,
    domainName,
    expiry,
    singleStorePolicy,
    storePolicies,
} from '../../config/config.test';
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
} from '../../../redux/actions/policies';
import { policies } from '../../../redux/reducers/policies';
import AppUtils from '../../../components/utils/AppUtils';

const utils = require('../../../redux/utils');

describe('Polices Reducer', () => {
    afterAll(() => {
        jest.spyOn(utils, 'getExpiredTime').mockRestore();
    });

    it('should load the policies', () => {
        const initialState = {};
        const action = {
            type: LOAD_POLICIES,
            payload: {
                policies: storePolicies,
                domainName: domainName,
                expiry: expiry,
            },
        };
        const expectedState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add a policy', () => {
        const initialState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ADD_POLICY,
            payload: {
                newPolicy: singleStorePolicy,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.policies['dom:policy.singlePolicy:0'] = singleStorePolicy;
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete policy1', () => {
        const initialState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_POLICY,
            payload: {
                policyName: 'dom:policy.policy1',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.policies['dom:policy.policy1:1'];
        delete expectedState.policies['dom:policy.policy1:2'];
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete policy version for policy 1 version2', () => {
        const initialState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_POLICY_VERSION,
            payload: {
                policyName: 'dom:policy.policy1',
                deletedVersion: '2',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.policies['dom:policy.policy1:2'];
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should set active version for policy1 to version 2', () => {
        const initialState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: SET_ACTIVE_POLICY_VERSION,
            payload: {
                policyName: 'dom:policy.policy1',
                version: '2',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.policies['dom:policy.policy1:2'].active = true;
        expectedState.policies['dom:policy.policy1:1'].active = false;
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    // TODO need to check if need to test this func also from add assertion
    it('should add assertion to policy version policy1:2', () => {
        let newAssertion = {
            role: 'dom:role.rol2',
            resource: 'dom:resource2',
            action: '*',
            effect: 'ALLOW',
            id: 17412,
            caseSensitive: false,
        };
        const initialState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ADD_ASSERTION_POLICY_VERSION,
            payload: {
                policyName: 'dom:policy.policy1',
                version: '2',
                newAssertion,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.policies['dom:policy.policy1:2'].assertions[17412] =
            newAssertion;
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete assertion from policy version policy2:0', () => {
        const initialState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_ASSERTION_POLICY_VERSION,
            payload: {
                policyName: 'dom:policy.policy2',
                version: '0',
                assertionId: 17390,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.policies['dom:policy.policy2:0'].assertions[17390];
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add assertion conditions to policy version policy1:1', () => {
        const initialState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const { conditionsList } = apiAssertionConditions;
        const action = {
            type: ADD_ASSERTION_CONDITIONS,
            payload: {
                policyName: 'dom:policy.policy1',
                version: '1',
                assertionId: 17326,
                conditionsList,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.policies[
            'dom:policy.policy1:1'
        ].assertions[17326].conditions = { conditionsList };
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add assertion conditions to policy version acl.ows.inbound:0 that already has assertion conditions', () => {
        const initialState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const { conditionsList } = apiAssertionConditions;
        const action = {
            type: ADD_ASSERTION_CONDITIONS,
            payload: {
                policyName: 'dom:policy.acl.ows.inbound',
                version: '0',
                assertionId: 34567,
                conditionsList,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.policies[
            'dom:policy.acl.ows.inbound:0'
        ].assertions[34567].conditions.conditionsList =
            expectedState.policies[
                'dom:policy.acl.ows.inbound:0'
            ].assertions[34567].conditions.conditionsList.concat(
                conditionsList
            );
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete assertion condition from policy version acl.ows.inbound:0', () => {
        const initialState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_ASSERTION_CONDITION,
            payload: {
                policyName: 'dom:policy.acl.ows.inbound',
                version: '0',
                assertionId: 34567,
                conditionId: 1,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.policies[
            'dom:policy.acl.ows.inbound:0'
        ].assertions[34567].conditions.conditionsList = expectedState.policies[
            'dom:policy.acl.ows.inbound:0'
        ].assertions[34567].conditions.conditionsList.filter(
            (condition) => condition.id !== 1
        );
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete assertion conditions from policy version acl.ows.inbound:0', () => {
        const initialState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_ASSERTION_CONDITIONS,
            payload: {
                policyName: 'dom:policy.acl.ows.inbound',
                version: '0',
                assertionId: 34567,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.policies['dom:policy.acl.ows.inbound:0']
            .assertions[34567].conditions;
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should make policies expires', () => {
        jest.spyOn(utils, 'getExpiredTime').mockReturnValue(-1);
        const initialState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: MAKE_POLICIES_EXPIRES,
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.expiry = -1;
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should return same state', () => {
        const initialState = {
            policies: storePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: RETURN_POLICIES,
        };
        const expectedState = AppUtils.deepClone(initialState);
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
});
