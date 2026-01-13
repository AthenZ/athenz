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
'use strict';

const apiUtils = require('../../../server/utils/apiUtils');
const testdata = require('../../../config/config')().testdata;
const humanUser = testdata.user1;

describe('apiUtils test', () => {
    test('should return pending member data', () => {
        let values = [
            {
                domainGroupMembersList: [
                    {
                        domainName: humanUser.domain,
                        members: [
                            {
                                memberName: humanUser.id,
                                memberGroups: [
                                    {
                                        groupName: 'testgroup',
                                        expiration: '2022-09-15T19:03:52.609Z',
                                        active: false,
                                        auditRef: 'test',
                                        requestTime: '2022-02-15T19:03:52.620Z',
                                        requestPrincipal: humanUser.id,
                                        reviewReminder:
                                            '2022-02-16T18:14:12.999Z',
                                        pendingState: 'DELETE',
                                    },
                                ],
                            },
                        ],
                    },
                ],
            },
            {
                domainRoleMembersList: [
                    {
                        domainName: `${humanUser.domain}.subdom`,
                        members: [
                            {
                                memberName: humanUser.id,
                                memberRoles: [
                                    {
                                        roleName: 'testrole1',
                                        active: false,
                                        auditRef: 'testing1',
                                        requestPrincipal: humanUser.id,
                                        requestTime: '2022-02-15T18:14:12.999Z',
                                        reviewReminder:
                                            '2022-02-17T18:14:12.999Z',
                                        pendingState: 'ADD',
                                    },
                                ],
                            },
                        ],
                    },
                ],
            },
        ];

        let data = apiUtils.getPendingDomainMemberData(values);
        expect(data).not.toBeNull;
        expect(data).toEqual({
            [`${humanUser.domain}.subdomuser.${humanUser.id_short}testrole1`]: {
                auditRef: '',
                category: 'role',
                domainName: `${humanUser.domain}.subdom`,
                expiryDate: null,
                memberName: humanUser.id,
                memberNameFull: null,
                requestPrincipal: humanUser.id,
                requestPrincipalFull: null,
                requestTime: '2022-02-15T18:14:12.999Z',
                reviewReminder: '2022-02-17T18:14:12.999Z',
                pendingState: 'ADD',
                roleName: 'testrole1',
                userComment: 'testing1',
            },
            [`${humanUser.domain}${humanUser.id}testgroup`]: {
                auditRef: '',
                category: 'group',
                domainName: humanUser.domain,
                expiryDate: '2022-09-15T19:03:52.609Z',
                memberName: humanUser.id,
                memberNameFull: null,
                requestPrincipal: humanUser.id,
                requestPrincipalFull: null,
                requestTime: '2022-02-15T19:03:52.620Z',
                reviewReminder: '2022-02-16T18:14:12.999Z',
                pendingState: 'DELETE',
                roleName: 'testgroup',
                userComment: 'test',
            },
        });
    });
    test('should return pending member promise', () => {
        let req = {
            clients: {
                zms: {
                    getPendingDomainGroupMembersList: jest.fn(),
                    getPendingDomainRoleMembersList: jest.fn(),
                },
            },
        };
        let params = {
            domainName: humanUser.domain,
        };
        let promises = apiUtils.getPendingDomainMembersPromise(params, req);
        expect(promises).not.toBeNull;
        expect(promises.length).toEqual(2);
    });
    test('should return extracted assertion id', () => {
        let data = {
            assertions: [
                {
                    role: 'testdomain:role.testrole',
                    resource: 'testdomain:testresource',
                    action: 'testaction',
                    effect: 'testeffect',
                    id: 1,
                },
                {
                    role: 'testdomain1:role.testrole1',
                    resource: 'testdomain1:testresource1',
                    action: 'testaction1',
                    effect: 'testeffect1',
                    id: 2,
                },
            ],
        };
        let assertionId = apiUtils.extractAssertionId(
            data,
            'testdomain1',
            'testrole1',
            'testaction1',
            'testeffect1',
            'testresource1'
        );
        expect(assertionId).not.toBeNull;
        expect(assertionId).toEqual(2);
    });
    test('should return getPolicy promise', () => {
        let req = {
            clients: {
                zms: {
                    getPolicy: jest.fn((x) => true),
                },
            },
        };
        let promises = apiUtils.getPolicy('testpolicy', 'testdomain', req);
        expect(promises).not.toBeNull;
        promises
            .then((data) => {})
            .catch((err) => {
                fail();
            });

        req = {
            clients: {
                zms: {
                    getPolicy: jest.fn((x) => {
                        throw 'testError';
                    }),
                },
            },
        };
        promises = apiUtils.getPolicy('testpolicy', 'testdomain', req);
        expect(promises).not.toBeNull;
        promises
            .then((data) => {
                fail();
            })
            .catch((err) => {});
    });
});
