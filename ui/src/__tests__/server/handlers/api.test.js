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

'use strict';

const api = require('../../../server/handlers/api');
const sinon = require('sinon');
const CLIENTS = require('../../../server/clients');

const config = {
    zms: 'https://zms.athenz.io',
    zmsLoginUrl: 'https://zms.athenz.io',
    athenzDomainService: 'athenz.unit-test',
    headerLinks: [],
    allProviders: [
        {
            id: 'aws_instance_launch_provider',
            name: 'AWS EC2/EKS/Fargate launches instances for the service',
        },
    ],
    createDomainMessage: '',
    servicePageConfig: '',
    productMasterLink: '',
    userData: () => {},
    userDomain: 'test-user-domain',
    serviceHeaderLinks: [],
    templates: ['openhouse'],
};
const secrets = {};
const expressApp = require('express')();
const request = require('supertest');
const bodyParser = require('body-parser');

describe('Fetchr Server API Test', () => {
    describe('success tests', () => {
        beforeAll(() => {
            sinon.stub(CLIENTS, 'load').returns(Promise.resolve());
            sinon.stub(CLIENTS, 'middleware').returns((req, res, next) => {
                req.clients = {
                    zms: {
                        putAssertion: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        deleteAssertion: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        deletePolicy: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        getDomain: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        postSubDomain: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        postUserDomain: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        deleteSubDomain: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        getDomainTemplateList: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        putDomainTemplate: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        getDomainList: (params, callback) => {
                            if (
                                params.roleMember &&
                                params.roleMember !=
                                    `${config.userDomain}.testuser`
                            ) {
                                // If the specified member is not included in any role in all domains, an empty array is responded.
                                callback(undefined, {
                                    names: [],
                                });
                                return;
                            }
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, {
                                      names: ['dom1', 'domabc1'],
                                  });
                        },
                        getSignedDomains: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        putMembership: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, {
                                      success: 'true',
                                  }),
                        deleteMembership: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        deletePendingMembership: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        getDomainRoleMembers: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        deleteDomainRoleMember: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        getPolicies: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, {
                                      list: [{ name: 'a' }, { name: 'b' }],
                                  }),
                        getPolicy: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        putPolicy: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        putMembershipDecision: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        getRole: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, {
                                      roleMembers: [
                                          { memberName: 'user.user1' },
                                      ],
                                      auditLog: [
                                          {
                                              action: 'read',
                                              member: 'user.user1',
                                              admin: 'user.useradmin',
                                          },
                                      ],
                                  }),
                        putRole: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        deleteRole: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        putRoleReview: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        putRoleMeta: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        getRoles: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        getRoleList: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        getPendingDomainGroupMembersList: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, {
                                      domainGroupMembersList: [],
                                  }),
                        getPendingDomainRoleMembersList: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, {
                                      domainRoleMembersList: [
                                          {
                                              domainName: 'avtest',
                                              members: [
                                                  {
                                                      memberName:
                                                          'user.gurleenk',
                                                      memberRoles: [
                                                          {
                                                              roleName:
                                                                  'audit_enabled_role',
                                                              expiration:
                                                                  '2020-07-17T19:00:00.000Z',
                                                              active: false,
                                                              auditRef: 'ee',
                                                              requestPrincipal:
                                                                  'user.abhijetv',
                                                              requestTime:
                                                                  '2020-04-10T04:59:33.325Z',
                                                          },
                                                      ],
                                                  },
                                                  {
                                                      memberName: 'user.jothip',
                                                      memberRoles: [
                                                          {
                                                              roleName:
                                                                  'audit_enabled_role2',
                                                              active: false,
                                                              auditRef:
                                                                  'jothi no expiry',
                                                              requestPrincipal:
                                                                  'user.abhijetv',
                                                              requestTime:
                                                                  '2020-04-10T06:04:29.337Z',
                                                          },
                                                      ],
                                                  },
                                                  {
                                                      memberName:
                                                          'user.palakas',
                                                      memberRoles: [
                                                          {
                                                              roleName:
                                                                  'audit_enabled_role2',
                                                              active: false,
                                                              auditRef: 'ee',
                                                              requestPrincipal:
                                                                  'user.abhijetv',
                                                              requestTime:
                                                                  '2020-04-10T05:11:32.667Z',
                                                          },
                                                      ],
                                                  },
                                              ],
                                          },
                                      ],
                                  }),
                        getServiceIdentities: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, {
                                      list: [{ name: 'a' }, { name: 'b' }],
                                  }),
                        getServiceIdentity: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        putServiceIdentity: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        deleteServiceIdentity: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        putPublicKeyEntry: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        deletePublicKeyEntry: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, { success: 'true' }),
                        getDomainTemplateDetailsList: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, {
                                      metaData: [
                                          {
                                              templateName: 'aws',
                                              description:
                                                  'AWS access template',
                                              currentVersion: 4,
                                              latestVersion: 1,
                                              timestamp:
                                                  '2020-04-28T00:00:00.000Z',
                                              autoUpdate: false,
                                          },
                                      ],
                                  }),
                        getResourceAccessList: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, {
                                      resources: {
                                          principal: 'user.dummy1',
                                          assertions: [
                                              {
                                                  dummyProperty: 'dummyValue'
                                              },
                                          ],
                                      },
                                  }),
                        getRolesForReview: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, {
                                      list: [
                                          {
                                              domainName: 'home.jtsang01',
                                              name: 'testrole',
                                              memberExpiryDays: 10,
                                              memberReviewDays: 0,
                                              serviceExpiryDays: 10,
                                              serviceReviewDays: 0,
                                              groupExpiryDays: 5,
                                              groupReviewDays: 5,
                                          },
                                      ],
                                  }),
                        getGroupsForReview: (params, callback) =>
                            params.forcefail
                                ? callback({ status: 404 }, null)
                                : callback(undefined, {
                                      list: [
                                          {
                                              domainName: 'home.jtsang01',
                                              name: 'testgroup',
                                              memberExpiryDays: 10,
                                              memberReviewDays: 0,
                                              serviceExpiryDays: 10,
                                              serviceReviewDays: 0,
                                              groupExpiryDays: 5,
                                              groupReviewDays: 5,
                                          },
                                      ],
                                  }),
                    },
                };
                next();
            });
            api.load(config, secrets).then(() => {
                expressApp.use(bodyParser.urlencoded({ extended: false }));
                expressApp.use(bodyParser.json());
                expressApp.use((req, res, next) => {
                    req.session = {
                        shortId: 'testuser',
                    };
                    req.csrfToken = () => '1234';
                    next();
                });
                api.route(expressApp);
            });
        });
        afterAll(() => {
            CLIENTS.load.restore();
            CLIENTS.middleware.restore();
        });
        it('putAssertion test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'assertion',
                            operation: 'create',
                            params: {
                                domainName: 'test',
                                policyName: 'testpol',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('deleteAssertion test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'assertion',
                            operation: 'delete',
                            params: {
                                domainName: 'test',
                                policyName: 'testpol',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('deletePolicy test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'policy',
                            operation: 'delete',
                            params: {
                                domainName: 'test',
                                policyName: 'testpol',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('getDomain test success', async () => {
            await request(expressApp)
                .get('/api/v1/domain;domain=testdom')
                .then((res) => {
                    expect(res.body).toEqual({ success: 'true' });
                });
        });
        it('postSubDomain test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'domain',
                            operation: 'create',
                            params: { domainName: 'test', parent: 'parentDom' },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('postUserDomain test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'domain',
                            operation: 'create',
                            params: {
                                name: 'test',
                                detail: {
                                    name: 'test',
                                    templates: {},
                                },
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('deleteSubDomain test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'domain',
                            operation: 'delete',
                            params: { domainName: 'test' },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('getDomainTemplate test success', async () => {
            await request(expressApp)
                .get('/api/v1/domain-templates;domain=testdom')
                .then((res) => {
                    expect(res.body).toEqual({ success: 'true' });
                });
        });
        it('postDomainTemplate test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'domain-templates',
                            operation: 'create',
                            params: { domainName: 'test' },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual([
                        { success: 'true' },
                        { success: 'true' },
                    ]);
                });
        });
        it('adminDomains test success', async () => {
            await request(expressApp)
                .get('/api/v1/admin-domains;domain=dom1')
                .then((res) => {
                    expect(res.body).toEqual([]);
                });
        });
        it('domainList test success', async () => {
            await request(expressApp)
                .get('/api/v1/domain-list')
                .then((res) => {
                    expect(res.body).toEqual([
                        { adminDomain: true, name: 'dom1' },
                        { adminDomain: true, name: 'domabc1' },
                    ]);
                });
        });
        it('getForm test success', async () => {
            await request(expressApp)
                .get('/api/v1/get-form')
                .then((res) => {
                    expect(res.body).toEqual('1234');
                });
        });
        it('putMembership test success', async () => {
            let member = {
                memberName: 'dummyMem',
            };
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'member',
                            operation: 'create',
                            params: {
                                category: 'role',
                                domainName: 'test',
                                collectionName: 'testrole',
                                memberName: 'dummyMem',
                                membership: {
                                    memberName: 'dummyMem',
                                },
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({
                        success: 'true',
                        memberFullName: null,
                    });
                });
        });
        it('deleteMembership test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'member',
                            operation: 'delete',
                            params: {
                                category: 'role',
                                domainName: 'test',
                                collectionName: 'testrole',
                                memberName: 'dummyMem',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('deletePendingMembership test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'pending-member',
                            operation: 'delete',
                            params: {
                                domainName: 'test',
                                roleName: 'testrole',
                                memberName: 'dummyMem',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('addMemberToRoles test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'member-multiple-roles',
                            operation: 'create',
                            params: {
                                domainName: 'test',
                                roles: ['testrole', 'testrole2'],
                                memberName: 'dummyMem',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual([
                        { success: 'true' },
                        { success: 'true' },
                    ]);
                });
        });
        it('getDomainRoleMembers test success', async () => {
            await request(expressApp)
                .get('/api/v1/role-members')
                .then((res) => {
                    expect(res.body).toEqual({ success: 'true' });
                });
        });
        it('deleteDomainRoleMember test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'role-members',
                            operation: 'delete',
                            params: {
                                domainName: 'test',
                                memberName: 'dummyMem',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('getPolicies test success', async () => {
            await request(expressApp)
                .get('/api/v1/policies')
                .then((res) => {
                    expect(res.body).toEqual([{ name: 'a' }, { name: 'b' }]);
                });
        });
        it('getPolicy test success', async () => {
            await request(expressApp)
                .get('/api/v1/policy')
                .then((res) => {
                    expect(res.body).toEqual({ success: 'true' });
                });
        });
        it('pending members decision test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'process-pending',
                            operation: 'create',
                            params: {
                                category: 'role',
                                domainName: 'test',
                                policyName: 'dummyPol',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('getProvider test success', async () => {
            await request(expressApp)
                .get('/api/v1/provider')
                .then((res) => {
                    expect(res.body).toEqual({
                        allProviders: [
                            {
                                id: 'aws_instance_launch_provider',
                                name: 'AWS EC2/EKS/Fargate launches instances for the service',
                            },
                        ],
                        provider: { aws_instance_launch_provider: 'not' },
                    });
                });
        });
        it('putDomainTemplate test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'provider',
                            operation: 'create',
                            params: {
                                domainName: 'test',
                                policyName: 'dummyPol',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        // NEW
        it('getRole test success', async () => {
            await request(expressApp)
                .get('/api/v1/role')
                .then((res) => {
                    expect(res.body).toEqual({
                        auditLog: [
                            {
                                action: 'read',
                                admin: 'user.useradmin',
                                member: 'user.user1',
                                adminFullName: null,
                                memberFullName: null,
                            },
                        ],
                        roleMembers: [
                            { memberName: 'user.user1', memberFullName: null },
                        ],
                    });
                });
        });
        it('putRole test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'role',
                            operation: 'create',
                            params: {
                                domainName: 'test',
                                roleName: 'dummyRole',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('deleteRole test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'role',
                            operation: 'delete',
                            params: {
                                domainName: 'test',
                                roleName: 'dummyRole',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('putRoleReview test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'role',
                            operation: 'update',
                            params: {
                                domainName: 'test',
                                roleName: 'dummyRole',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('putRoleMeta test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'meta',
                            operation: 'create',
                            params: {
                                category: 'role',
                                domainName: 'test',
                                principalName: 'dummyRole',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('getRoles test success', async () => {
            await request(expressApp)
                .get('/api/v1/roles')
                .then((res) => {
                    expect(res.body).toEqual({ success: 'true' });
                });
        });
        it('getRoleList test success', async () => {
            await request(expressApp)
                .get('/api/v1/role-list')
                .then((res) => {
                    expect(res.body).toEqual({ success: 'true' });
                });
        });
        it('getPendingMembers test success', async () => {
            await request(expressApp)
                .get('/api/v1/pending-approval')
                .then((res) => {
                    expect(res.body).toEqual({
                        'avtestuser.gurleenkaudit_enabled_role': {
                            domainName: 'avtest',
                            memberName: 'user.gurleenk',
                            roleName: 'audit_enabled_role',
                            userComment: 'ee',
                            auditRef: '',
                            category: 'role',
                            requestPrincipal: 'user.abhijetv',
                            requestTime: '2020-04-10T04:59:33.325Z',
                            expiryDate: '2020-07-17T19:00:00.000Z',
                            memberNameFull: null,
                            requestPrincipalFull: null,
                        },
                        'avtestuser.jothipaudit_enabled_role2': {
                            domainName: 'avtest',
                            memberName: 'user.jothip',
                            category: 'role',
                            roleName: 'audit_enabled_role2',
                            userComment: 'jothi no expiry',
                            auditRef: '',
                            requestPrincipal: 'user.abhijetv',
                            requestTime: '2020-04-10T06:04:29.337Z',
                            expiryDate: null,
                            memberNameFull: null,
                            requestPrincipalFull: null,
                        },
                        'avtestuser.palakasaudit_enabled_role2': {
                            domainName: 'avtest',
                            memberName: 'user.palakas',
                            category: 'role',
                            roleName: 'audit_enabled_role2',
                            userComment: 'ee',
                            auditRef: '',
                            requestPrincipal: 'user.abhijetv',
                            requestTime: '2020-04-10T05:11:32.667Z',
                            expiryDate: null,
                            memberNameFull: null,
                            requestPrincipalFull: null,
                        },
                    });
                });
        });
        it('getPendingMembersCount test success', async () => {
            await request(expressApp)
                .get('/api/v1/pending-approval-domain-count')
                .then((res) => {
                    expect(res.body).toEqual(1);
                });
        });
        it('getPendingMembersByDomain test success', async () => {
            await request(expressApp)
                .get('/api/v1/pending-approval-domain')
                .send({
                    params: {
                        domainName: 'avtest',
                    },
                })
                .then((res) => {
                    expect(res.body).toEqual({
                        'avtestuser.gurleenkaudit_enabled_role': {
                            domainName: 'avtest',
                            memberName: 'user.gurleenk',
                            roleName: 'audit_enabled_role',
                            userComment: 'ee',
                            auditRef: '',
                            category: 'role',
                            requestPrincipal: 'user.abhijetv',
                            requestTime: '2020-04-10T04:59:33.325Z',
                            expiryDate: '2020-07-17T19:00:00.000Z',
                            memberNameFull: null,
                            requestPrincipalFull: null,
                        },
                        'avtestuser.jothipaudit_enabled_role2': {
                            domainName: 'avtest',
                            memberName: 'user.jothip',
                            category: 'role',
                            roleName: 'audit_enabled_role2',
                            userComment: 'jothi no expiry',
                            auditRef: '',
                            requestPrincipal: 'user.abhijetv',
                            requestTime: '2020-04-10T06:04:29.337Z',
                            expiryDate: null,
                            memberNameFull: null,
                            requestPrincipalFull: null,
                        },
                        'avtestuser.palakasaudit_enabled_role2': {
                            domainName: 'avtest',
                            memberName: 'user.palakas',
                            category: 'role',
                            roleName: 'audit_enabled_role2',
                            userComment: 'ee',
                            auditRef: '',
                            requestPrincipal: 'user.abhijetv',
                            requestTime: '2020-04-10T05:11:32.667Z',
                            expiryDate: null,
                            memberNameFull: null,
                            requestPrincipalFull: null,
                        },
                    });
                });
        });
        it('getServices test success', async () => {
            await request(expressApp)
                .get('/api/v1/services')
                .then((res) => {
                    expect(res.body).toEqual([{ name: 'a' }, { name: 'b' }]);
                });
        });
        it('search domains test success', async () => {
            await request(expressApp)
                .get('/api/v1/search-domain;domainName=abc')
                .then((res) => {
                    expect(res.body).toEqual([
                        {
                            adminDomain: true,
                            name: 'domabc1',
                            userDomain: true,
                        },
                    ]);
                });
        });
        it('getService identity test success', async () => {
            await request(expressApp)
                .get('/api/v1/service')
                .then((res) => {
                    expect(res.body).toEqual({ success: 'true' });
                });
        });
        it('create service identity test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'service',
                            operation: 'create',
                            params: {
                                domainName: 'test',
                                roleName: 'dummyRole',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('delete service identity test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'service',
                            operation: 'delete',
                            params: {
                                domainName: 'test',
                                roleName: 'dummyRole',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('create public key entry test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'key',
                            operation: 'create',
                            params: {
                                domainName: 'test',
                                roleName: 'dummyRole',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('delete public key entry test success', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'key',
                            operation: 'delete',
                            params: {
                                domainName: 'test',
                                roleName: 'dummyRole',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.body.g0.data).toEqual({ success: 'true' });
                });
        });
        it('get status test success', async () => {
            await request(expressApp)
                .get('/api/v1/status')
                .then((res) => {
                    expect(res.body).toEqual('ok');
                });
        });
        it('get user test success', async () => {
            await request(expressApp)
                .get('/api/v1/user')
                .then((res) => {
                    expect(res.body).toEqual({ userId: 'testuser' });
                });
        });
        it('get auth options test success', async () => {
            await request(expressApp)
                .get('/api/v1/auth-options')
                .then((res) => {
                    expect(res.body).toEqual({
                        zmsLoginUrl: 'https://zms.athenz.io',
                        athenzDomainService: 'athenz.unit-test',
                    });
                });
        });
        it('get header details test success', async () => {
            await request(expressApp)
                .get('/api/v1/header-details')
                .then((res) => {
                    expect(res.body).toEqual({
                        headerLinks: [],
                        userId: 'testuser',
                        createDomainMessage: '',
                        productMasterLink: '',
                    });
                });
        });
        it('service page config test success', async () => {
            await request(expressApp)
                .get('/api/v1/service-page-config')
                .then((res) => {
                    expect(res.body).toEqual({ servicePageConfig: '' });
                });
        });
        it('getDomainTemplateDetailsList test success', async () => {
            await request(expressApp)
                .get('/api/v1/templates;name=testdom1')
                .then((res) => {
                    expect(res.body).toEqual([
                        {
                            templateName: 'aws',
                            description: 'AWS access template',
                            currentVersion: 4,
                            latestVersion: 1,
                            timestamp: '2020-04-28T00:00:00.000Z',
                            autoUpdate: false,
                        },
                    ]);
                });
        });
    });
    describe('failure tests', () => {
        it('putAssertion test failure', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'assertion',
                            operation: 'create',
                            params: {
                                domainName: 'test',
                                policyName: 'testpol',
                                forcefail: 'yes',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.status).toEqual(404);
                });
        });
        it('deleteAssertion test failure', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'assertion',
                            operation: 'delete',
                            params: {
                                domainName: 'test',
                                policyName: 'testpol',
                                forcefail: 'yes',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.status).toEqual(404);
                });
        });
        it('deletePolicy test failure', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'policy',
                            operation: 'delete',
                            params: {
                                domainName: 'test',
                                policyName: 'testpol',
                                forcefail: 'yes',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.status).toEqual(404);
                });
        });
        it('create service identity test failure', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'service',
                            operation: 'create',
                            params: {
                                domainName: 'test',
                                roleName: 'dummyRole',
                                forcefail: 'yes',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.status).toEqual(404);
                });
        });
        it('delete service identity test failure', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'service',
                            operation: 'delete',
                            params: {
                                domainName: 'test',
                                roleName: 'dummyRole',
                                forcefail: 'yes',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.status).toEqual(404);
                });
        });
        it('create public key entry test failure', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'key',
                            operation: 'create',
                            params: {
                                domainName: 'test',
                                roleName: 'dummyRole',
                                forcefail: 'yes',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.status).toEqual(404);
                });
        });
        it('delete public key entry test failure', async () => {
            await request(expressApp)
                .post('/api/v1')
                .send({
                    requests: {
                        g0: {
                            resource: 'key',
                            operation: 'delete',
                            params: {
                                domainName: 'test',
                                roleName: 'dummyRole',
                                forcefail: 'yes',
                            },
                        },
                    },
                })
                .set('Accept', 'application/json')
                .set('Content-Type', 'application/json')
                .then((res) => {
                    expect(res.status).toEqual(404);
                });
        });
        it('getResourceAccessList test success', async () => {
            await request(expressApp)
                .get('/api/v1/resource-access')
                .then((res) => {
                    expect(res.body).toEqual({
                        resources: {
                            principal: 'user.dummy1',
                            assertions: [
                                {
                                    dummyProperty: 'dummyValue'
                                },
                            ],
                        },
                    });
                });
        });
        it('getRolesForReview test success', async () => {
            await request(expressApp)
                .get('/api/v1/roles-review')
                .then((res) => {
                    expect(res.body).toEqual([
                        {
                            domainName: 'home.jtsang01',
                            name: 'testrole',
                            memberExpiryDays: 10,
                            memberReviewDays: 0,
                            serviceExpiryDays: 10,
                            serviceReviewDays: 0,
                            groupExpiryDays: 5,
                            groupReviewDays: 5,
                        },
                    ]);
                });
        });
        it('getGroupsForReview test success', async () => {
            await request(expressApp)
                .get('/api/v1/groups-review')
                .then((res) => {
                    expect(res.body).toEqual([
                        {
                            domainName: 'home.jtsang01',
                            name: 'testgroup',
                            memberExpiryDays: 10,
                            memberReviewDays: 0,
                            serviceExpiryDays: 10,
                            serviceReviewDays: 0,
                            groupExpiryDays: 5,
                            groupReviewDays: 5,
                        },
                    ]);
                });
        });
    });
});
