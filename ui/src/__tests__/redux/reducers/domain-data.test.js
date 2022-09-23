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
import { domainName, expiry } from '../../config/config.test';
import AppUtils from '../../../components/utils/AppUtils';
import {
    UPDATE_BELL_PENDING_MEMBERS,
    LOAD_DOMAIN_DATA,
    LOAD_DOMAIN_HISTORY_TO_STORE,
    UPDATE_BUSINESS_SERVICE_IN_STORE,
} from '../../../redux/actions/domain-data';
import { domainData } from '../../../redux/reducers/domain-data';
import {
    UPDATE_SETTING_TO_STORE,
    UPDATE_TAGS_TO_STORE,
} from '../../../redux/actions/collections';
import { storeDomainData } from '../config/domainData.test';

describe('DomainData Reducer', () => {
    it('should load the domainData', () => {
        const initialState = {};
        const action = {
            type: LOAD_DOMAIN_DATA,
            payload: {
                domainData: storeDomainData,
                domainName: domainName,
                expiry: expiry,
            },
        };
        const expectedState = {
            domainData: storeDomainData,
            domainName: domainName,
            expiry: expiry,
        };
        const newState = domainData(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should update setting', () => {
        let newSettings = {
            groupExpiryDays: '50',
            memberExpiryDays: '100',
            roleCertExpiryMins: '',
            serviceExpiryDays: '',
            tokenExpiryMins: '20',
        };
        const initialState = {
            domainData: storeDomainData,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_SETTING_TO_STORE,
            payload: {
                collectionSettings: newSettings,
                category: 'domain',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.domainData.groupExpiryDays = '50';
        expectedState.domainData.memberExpiryDays = '100';
        expectedState.domainData.tokenExpiryMins = '20';
        expectedState.domainData.serviceExpiryDays = '';
        expectedState.domainData.roleCertExpiryMins = '';
        const newState = domainData(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add tags', () => {
        let newTags = {
            tag1: { list: ['tagValue1', 'tagValue2'] },
            tag2: { list: ['tagValue3'] },
            newtag: { list: ['newtagvalue1', 'newtagvalue2'] },
        };
        const initialState = {
            domainData: storeDomainData,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionTags: newTags,
                category: 'domain',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.domainData.tags = newTags;
        const newState = domainData(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete tag', () => {
        let newTags = {
            tag1: { list: ['tagValue1', 'tagValue2'] },
        };
        const initialState = {
            domainData: storeDomainData,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionTags: newTags,
                category: 'domain',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.domainData.tags.tag2;
        const newState = domainData(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should edit tag', () => {
        let newTags = {
            tag1: { list: ['newtagValue1', 'tagValue2'] },
            tag2: { list: ['tagValue3', 'addtagValue4'] },
        };
        const initialState = {
            domainData: storeDomainData,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionTags: newTags,
                category: 'domain',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.domainData.tags.tag2.list.push('addtagValue4');
        expectedState.domainData.tags.tag1.list[0] = 'newtagValue1';
        const newState = domainData(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should update business service in the store ', () => {
        const initialState = {
            domainData: storeDomainData,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_BUSINESS_SERVICE_IN_STORE,
            payload: {
                businessServiceName: 'testBusinessService',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.domainData.businessService = 'testBusinessService';
        const newState = domainData(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should load domain history', () => {
        let history = [
            {
                action: 'putrolemeta',
                who: 'user.user1',
                whoFull: 'user1',
                whatEntity: 'dom.user1',
                when: '2022-09-12T05:59:10.965Z',
                details:
                    '{"name": "redux", "selfServe": "false", "memberExpiryDays": "null", "serviceExpiryDays": "null", "groupExpiryDays": "null", "tokenExpiryMins": "null", "certExpiryMins": "null", "memberReviewDays": "null", "serviceReviewDays": "null", "groupReviewDays": "null", "reviewEnabled": "true", "notifyRoles": "null", "signAlgorithm": "null", "userAuthorityFilter": "", "userAuthorityExpiration": ""}',
                epoch: 1662962350965,
                why: 'Updated domain Meta using Athenz UI',
            },
            {
                action: 'putrole',
                who: 'user.user1',
                whoFull: 'user1',
                whatEntity: 'redux',
                when: '2022-09-08T10:26:56.582Z',
                details:
                    '{"name": "redux", "trust": "null", "added-members": [{"member": "home.user1:group.redux2", "approved": true, "system-disabled": 0}]}',
                epoch: 1662632816582,
                why: 'null',
            },
        ];
        let storeDataWithoutHistory = AppUtils.deepClone(storeDomainData);
        delete storeDataWithoutHistory.history;
        const initialState = {
            domainData: storeDataWithoutHistory,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: LOAD_DOMAIN_HISTORY_TO_STORE,
            payload: {
                history: history,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.domainData.history = history;
        const newState = domainData(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add bell pending member', () => {
        const initialState = {
            domainData: storeDomainData,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_BELL_PENDING_MEMBERS,
            payload: {
                memberName: 'user.user3',
                collection: 'dom:role.redux3',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.domainData.bellPendingMembers[
            'dom:role.redux3user.user3'
        ] = true;
        const newState = domainData(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should delete bell pending member', () => {
        const initialState = {
            domainData: storeDomainData,
            domainName: 'dom1',
            expiry: expiry,
        };
        const action = {
            type: UPDATE_BELL_PENDING_MEMBERS,
            payload: {
                memberName: 'user.user1',
                collection: 'dom1:role.redux1',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.domainData.bellPendingMembers[
            'dom1:role.redux1user.user1'
        ];
        const newState = domainData(initialState, action);
        expect(newState).toEqual(expectedState);
    });
});
