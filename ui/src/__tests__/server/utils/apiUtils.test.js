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

describe('apiUtils test', () => {
    test('should return pending member data', () => {
        let values = [
            {
                domainGroupMembersList: [
                    {
                        domainName: 'home.craman',
                        members: [
                            {
                                memberName: 'user.craman',
                                memberGroups: [
                                    {
                                        groupName: 'testgroup',
                                        expiration: '2022-09-15T19:03:52.609Z',
                                        active: false,
                                        auditRef: 'test',
                                        requestTime: '2022-02-15T19:03:52.620Z',
                                        requestPrincipal: 'user.craman',
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
                        domainName: 'home.craman.subdom',
                        members: [
                            {
                                memberName: 'user.craman',
                                memberRoles: [
                                    {
                                        roleName: 'testrole1',
                                        active: false,
                                        auditRef: 'testing1',
                                        requestPrincipal: 'user.craman',
                                        requestTime: '2022-02-15T18:14:12.999Z',
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
            'home.craman.subdomuser.cramantestrole1': {
                auditRef: '',
                category: 'role',
                domainName: 'home.craman.subdom',
                expiryDate: null,
                memberName: 'user.craman',
                memberNameFull: null,
                requestPrincipal: 'user.craman',
                requestPrincipalFull: null,
                requestTime: '2022-02-15T18:14:12.999Z',
                roleName: 'testrole1',
                userComment: 'testing1',
            },
            'home.cramanuser.cramantestgroup': {
                auditRef: '',
                category: 'group',
                domainName: 'home.craman',
                expiryDate: '2022-09-15T19:03:52.609Z',
                memberName: 'user.craman',
                memberNameFull: null,
                requestPrincipal: 'user.craman',
                requestPrincipalFull: null,
                requestTime: '2022-02-15T19:03:52.620Z',
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
            domainName: 'home.craman',
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
