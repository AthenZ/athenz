/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { _ } from 'lodash';
import { singleStorePolicy, configStorePolicies } from '../config/policy.test';
import {
    apiAssertionConditions,
    domainName,
    expiry,
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
import { configStoreRoles } from '../config/role.test';
import { UPDATE_TAGS_TO_STORE } from '../../../redux/actions/collections';
import { roles } from '../../../redux/reducers/roles';

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
                policies: configStorePolicies,
                domainName: domainName,
                expiry: expiry,
            },
        };
        const expectedState = {
            policies: configStorePolicies,
            domainName: domainName,
            expiry: expiry,
        };
        const newState = policies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add a policy', () => {
        const initialState = {
            policies: configStorePolicies,
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
            policies: configStorePolicies,
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
            policies: configStorePolicies,
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
            policies: configStorePolicies,
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
            policies: configStorePolicies,
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
            policies: configStorePolicies,
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
            policies: configStorePolicies,
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
            policies: configStorePolicies,
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
            policies: configStorePolicies,
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
            policies: configStorePolicies,
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
            policies: configStorePolicies,
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
            policies: configStorePolicies,
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
    it('should add policy tag the store', () => {
        const initialState = {
            policies: AppUtils.deepClone(configStorePolicies),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:policy.policy1',
                collectionWithTags: {
                    ...configStorePolicies['dom:policy.policy1:1'],
                    tags: { tag: { list: ['tag1', 'tag2'] } },
                },
                category: 'policy',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.policies['dom:policy.policy1:1'].tags = {
            tag: { list: ['tag1', 'tag2'] },
        };
        const newState = policies(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should edit tags from policy', () => {
        const initialState = {
            policies: AppUtils.deepClone(configStorePolicies),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:policy.policy1',
                collectionWithTags: {
                    ...configStorePolicies['dom:policy.policy1:2'],
                    tags: {
                        tag: { list: ['tag1', 'tag3'] },
                        tag2: { list: ['tag3', 'tag4'] },
                    },
                },
                category: 'policy',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.policies['dom:policy.policy1:2'].tags = {
            tag: { list: ['tag1', 'tag3'] },
            tag2: { list: ['tag3', 'tag4'] },
        };
        const newState = policies(initialState, action);
        expect(newState).toEqual(expectedState);
    });

    it('should delete tag from store', () => {
        const initialState = {
            policies: AppUtils.deepClone(configStorePolicies),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:policy.policy1',
                collectionWithTags: {
                    ...configStorePolicies['dom:policy.policy1:2'],
                    tags: { tag: { list: ['tag1'] } },
                },
                category: 'policy',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.policies['dom:policy.policy1:2'].tags = {
            tag: { list: ['tag1'] },
        };
        const newState = policies(initialState, action);
        expect(newState).toEqual(expectedState);
    });
});
