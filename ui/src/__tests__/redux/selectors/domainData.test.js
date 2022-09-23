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
import { domainName, expiry } from '../../config/config.test';
import {
    selectDomainAuditEnabled,
    selectDomainData,
    selectDomainTags,
    selectHeaderDetails,
    selectHistoryRows,
} from '../../../redux/selectors/domainData';
import { storeDomainData } from '../config/domainData.test';

// TODO roy - need to increase coverage
describe('test domain data selectors', () => {
    const stateWithDomainData = {
        domainData: {
            domainName,
            expiry,
            domainData: storeDomainData,
        },
    };
    const stateWithoutDomainData = {
        domainData: {
            domainName,
        },
    };
    describe('test selectDomainData selector', () => {
        it('should return domain data', () => {
            expect(selectDomainData(stateWithDomainData)).toEqual(
                storeDomainData
            );
        });
        it('should return empty object', () => {
            expect(selectDomainData(stateWithoutDomainData)).toEqual({});
        });
    });
    describe('test selectDomainAuditEnabled selector', () => {
        it('should return audit enabled', () => {
            let auditEnabled = false;
            expect(selectDomainAuditEnabled(stateWithDomainData)).toEqual(
                auditEnabled
            );
        });
    });

    describe('test selectDomainTags selector', () => {
        it('should return tags', () => {
            const tags = {
                tag1: { list: ['tagValue1', 'tagValue2'] },
                tag2: { list: ['tagValue3'] },
            };
            expect(selectDomainTags(stateWithDomainData)).toEqual(tags);
        });
        it('should return empty object', () => {
            expect(selectDomainTags(stateWithoutDomainData)).toEqual({});
        });
    });
    describe('test selectHistoryRows selector', () => {
        it('should return history', () => {
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
            expect(selectHistoryRows(stateWithDomainData)).toEqual(history);
        });
        it('should return empty object', () => {
            expect(selectHistoryRows(stateWithoutDomainData)).toEqual([]);
        });
    });
    describe('test selectBusinessServices selector', () => {
        it('should return business services', () => {
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
            expect(selectHistoryRows(stateWithDomainData)).toEqual(history);
        });
        it('should return empty object', () => {
            expect(selectHistoryRows(stateWithoutDomainData)).toEqual([]);
        });
    });
});
