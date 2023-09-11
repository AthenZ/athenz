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
import {
    buildPolicyMapKey,
    getCurrentTime,
    getExpiredTime,
    getExpiryTime,
    getFullName,
    isExpired,
    mapToList,
    policyListToMap,
} from '../../redux/utils';
import { configStorePolicies, apiPolicies } from './config/policy.test';
import { apiAssertionConditions, modified } from '../config/config.test';
import { _ } from 'lodash';
import { expiryTimeInMilliseconds, roleDelimiter } from '../../redux/config';

describe('test redux utils', () => {
    const fakeDateNow = 1530518207007;
    beforeAll(() => {
        jest.spyOn(global.Date, 'now').mockReturnValue(fakeDateNow);
    });
    afterAll(() => {
        jest.spyOn(global.Date, 'now').mockRestore();
    });
    it('test listToMap', () => {});
    it('test mapToList', () => {
        const expected = [
            {
                name: 'dom:policy.admin',
                modified: modified,
                assertions: {
                    17100: {
                        role: 'dom:role.admin',
                        resource: 'dom:*',
                        action: '*',
                        effect: 'ALLOW',
                        id: 17100,
                    },
                },
                version: '0',
                active: true,
            },
            {
                name: 'dom:policy.acl.ows.inbound',
                modified: modified,
                assertions: {
                    34567: {
                        role: 'dom:role.acl.ows.inbound-test1',
                        resource: 'dom:ows',
                        action: 'TCP-IN:1024-65535:4443-4443',
                        effect: 'ALLOW',
                        id: 34567,
                        conditions: apiAssertionConditions,
                    },
                    98765: {
                        role: 'dom:role.role1',
                        resource: 'dom:test',
                        action: '*',
                        effect: 'ALLOW',
                        id: 98765,
                    },
                },
                version: '0',
                active: true,
            },
            {
                name: 'dom:policy.acl.ows.outbound',
                modified: modified,
                tags: {
                    tag: {
                        list: ['tag1'],
                    },
                    tag2: {
                        list: ['tag3'],
                    },
                },
                assertions: {
                    76543: {
                        role: 'dom:role.acl.ows.outbound-test2',
                        resource: 'dom:ows',
                        action: 'TCP-OUT:1024-65535:4443-4443',
                        effect: 'ALLOW',
                        id: 76543,
                        conditions: apiAssertionConditions,
                    },
                },
                version: '0',
                active: true,
            },
            {
                name: 'dom:policy.policy1',
                modified: modified,
                assertions: {
                    17326: {
                        role: 'dom:role.role1',
                        resource: 'dom:test',
                        action: '*',
                        effect: 'ALLOW',
                        id: 17326,
                    },
                },
                version: '1',
                active: true,
            },
            {
                name: 'dom:policy.policy1',
                modified: modified,
                tags: {
                    tag: {
                        list: ['tag1', 'tag2'],
                    },
                    tag2: {
                        list: ['tag3'],
                    },
                },
                assertions: {
                    17379: {
                        role: 'dom:role.role2',
                        resource: 'dom:test2',
                        action: '*',
                        effect: 'DENY',
                        id: 17379,
                    },
                },
                version: '2',
                active: false,
            },
            {
                name: 'dom:policy.policy2',
                modified: modified,
                assertions: {
                    17380: {
                        role: 'dom:role.role3',
                        resource: 'dom:testing',
                        action: '*',
                        effect: 'DENY',
                        id: 17380,
                    },
                    17390: {
                        role: 'dom:role.role4',
                        resource: 'dom:resource2',
                        action: '*',
                        effect: 'DENY',
                        id: 17390,
                    },
                },
                version: '0',
                active: false,
            },
        ];
        expect(mapToList(configStorePolicies)).toEqual(expected);
    });
    it('test policyListToMap', () => {
        expect(policyListToMap(apiPolicies)).toEqual(configStorePolicies);
    });
    it('test buildPolicyMapKey', () => {
        let policyName = 'dom:policy.policy1';
        let version = '0';
        let expected = policyName + ':' + version;
        expect(buildPolicyMapKey(policyName, version)).toEqual(expected);
    });
    it('test getFullName', () => {
        let domain = 'dom';
        let role = 'role1';
        expect(getFullName(domain, roleDelimiter, role)).toBe(
            domain + ':role.' + role
        );
    });
    it('test getExpiryTime', () => {
        expect(getExpiryTime()).toBe(fakeDateNow + expiryTimeInMilliseconds);
    });
    it('test getExpiredTime', () => {
        expect(getExpiredTime()).toBe(fakeDateNow - expiryTimeInMilliseconds);
    });
    it('test isExpired', () => {
        // should return false
        expect(isExpired(fakeDateNow + expiryTimeInMilliseconds)).toBe(false);
        // should return true
        expect(isExpired(fakeDateNow)).toBe(true);
        // should return true - the argument is NaN
        expect(
            isExpired((fakeDateNow + expiryTimeInMilliseconds).toString())
        ).toBe(true);
    });
    it('test getCurrentTime', () => {
        expect(getCurrentTime()).toEqual(new Date(fakeDateNow).toISOString());
    });
});
