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
let req = require('supertest');
import Fetchr from 'fetchr';
import API from '../api.js';
let api = API(req);
const sinon = require('sinon');
let myDataService, fetchrStub, result, myDataServiceErr;
const DATA = {
    a: 1,
};

describe('Fetchr Client API Test', () => {
    describe('listUserDomains test', () => {
        it('listUserDomains test success', async () => {
            myDataService = {
                name: 'domain-list',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.listUserDomains('dummy');
            expect(result).toEqual(DATA);
        });
        it('listUserDomains test error', async () => {
            myDataServiceErr = {
                name: 'domain-list',
                read: function (req, resource, params, config, callback) {
                    callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.listUserDomains('dummy').catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('listAdminDomains test', () => {
        it('listAdminDomains test success', async () => {
            myDataService = {
                name: 'admin-domains',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.listAdminDomains('dummy');
            expect(result).toEqual(DATA);
        });
        it('listAdminDomains test error', async () => {
            myDataServiceErr = {
                name: 'admin-domains',
                read: function (req, resource, params, config, callback) {
                    callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.listAdminDomains('dummy').catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getDomain test', () => {
        it('getDomain test success', async () => {
            myDataService = {
                name: 'domain',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getDomain('dummy');
            expect(result).toEqual(DATA);
        });
        it('getDomain test error', async () => {
            myDataServiceErr = {
                name: 'domain',
                read: function (req, resource, params, config, callback) {
                    callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getDomain('dummy').catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('createSubDomain test', () => {
        it('createSubDomain test success', async () => {
            myDataService = {
                name: 'domain',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.createSubDomain(
                'dummyParent',
                'dummySub',
                'user.admin',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('createSubDomain test error', async () => {
            myDataServiceErr = {
                name: 'domain',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .createSubDomain(
                    'dummyParent',
                    'dummySub',
                    'user.admin',
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('createUserDomain test', () => {
        it('createUserDomain test success', async () => {
            myDataService = {
                name: 'domain',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.createUserDomain('dummyDom', '1234');
            expect(result).toEqual(DATA);
        });
        it('createUserDomain test error', async () => {
            myDataServiceErr = {
                name: 'domain',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.createUserDomain('dummyDom', '1234').catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getRoleMembers test', () => {
        it('getRoleMembers test success', async () => {
            myDataService = {
                name: 'role-members',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getRoleMembers('dummy');
            expect(result).toEqual(DATA);
        });
        it('getRoleMembers test error', async () => {
            myDataServiceErr = {
                name: 'role-members',
                read: function (req, resource, params, config, callback) {
                    callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getRoleMembers('dummy').catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('listRoles test', () => {
        it('listRoles test success', async () => {
            myDataService = {
                name: 'roles',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.listRoles('dummy');
            expect(result).toEqual([]);
        });
        it('listRoles test error', async () => {
            myDataServiceErr = {
                name: 'roles',
                read: function (req, resource, params, config, callback) {
                    callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.listRoles('dummy').catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getRoles test', () => {
        it('getRoles test success', async () => {
            myDataService = {
                name: 'roles',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getRoles('dummy');
            expect(result).toEqual([]);
        });
        it('getRoles test error', async () => {
            myDataServiceErr = {
                name: 'roles',
                read: function (req, resource, params, config, callback) {
                    callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getRoles('dummy').catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getRole test', () => {
        it('getRole test success', async () => {
            myDataService = {
                name: 'role',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getRole('dummyDom', 'dummyRole');
            expect(result).toEqual(DATA);
        });
        it('getRole test error', async () => {
            myDataServiceErr = {
                name: 'role',
                read: function (req, resource, params, config, callback) {
                    callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getRole('dummyDom', 'dummyRole').catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getPendingDomainMembersList test', () => {
        it('getPendingDomainMembersList test success', async () => {
            myDataService = {
                name: 'pending-approval',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getPendingDomainMembersList();
            expect(result).toEqual(DATA);
        });
        it('getPendingDomainMembersList test error', async () => {
            myDataServiceErr = {
                name: 'pending-approval',
                read: function (req, resource, params, config, callback) {
                    callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getPendingDomainMembersList().catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('processPending test', () => {
        it('processPending test success', async () => {
            myDataService = {
                name: 'process-pending',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.processPending(
                'dummyDom',
                'dummyRole',
                'dummyMem',
                'dummyAuditRef',
                {},
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('processPending test error', async () => {
            myDataServiceErr = {
                name: 'process-pending',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .processPending(
                    'dummyDom',
                    'dummyRole',
                    'dummyMem',
                    'dummyAuditRef',
                    {},
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('addRole test', () => {
        it('addRole test success', async () => {
            myDataService = {
                name: 'role',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.addRole(
                'dummyDom',
                'dummyRole',
                {},
                'dummyAuditRef',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('addRole test error', async () => {
            myDataServiceErr = {
                name: 'role',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .addRole('dummyDom', 'dummyRole', {}, 'dummyAuditRef', '1234')
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('deleteRole test', () => {
        it('deleteRole test success', async () => {
            myDataService = {
                name: 'role',
                delete: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.deleteRole(
                'dummyDom',
                'dummyRole',
                'dummyAuditRef',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('deleteRole test error', async () => {
            myDataServiceErr = {
                name: 'role',
                delete: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .deleteRole('dummyDom', 'dummyRole', 'dummyAuditRef', '1234')
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('reviewRole test', () => {
        it('reviewRole test success', async () => {
            myDataService = {
                name: 'role',
                update: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.reviewRole(
                'dummyDom',
                'dummyRole',
                {},
                'dummyAuditRef',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('reviewRole test error', async () => {
            myDataServiceErr = {
                name: 'role',
                update: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .reviewRole(
                    'dummyDom',
                    'dummyRole',
                    {},
                    'dummyAuditRef',
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('deleteRoleMember test', () => {
        it('deleteRoleMember test success', async () => {
            myDataService = {
                name: 'role-members',
                delete: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.deleteRoleMember(
                'dummyDom',
                'dummyMember',
                'dummyAuditRef',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('deleteRoleMember test error', async () => {
            myDataServiceErr = {
                name: 'role-members',
                delete: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .deleteRoleMember(
                    'dummyDom',
                    'dummyMember',
                    'dummyAuditRef',
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('addMember test', () => {
        it('addMember test success', async () => {
            myDataService = {
                name: 'member',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.addMember(
                'dummyDom',
                'dummyRole',
                'dummyMem',
                {},
                'dummyAuditRef',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('addMember test error', async () => {
            myDataServiceErr = {
                name: 'member',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .addMember(
                    'dummyDom',
                    'dummyRole',
                    'dummyMem',
                    {},
                    'dummyAuditRef',
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('addMemberToRoles test', () => {
        it('addMemberToRoles test success', async () => {
            myDataService = {
                name: 'member-multiple-roles',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.addMemberToRoles(
                'dummyDom',
                'dummyRole',
                'dummyMem',
                {},
                'dummyAuditRef',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('addMemberToRoles test error', async () => {
            myDataServiceErr = {
                name: 'member-multiple-roles',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .addMemberToRoles(
                    'dummyDom',
                    'dummyRole',
                    'dummyMem',
                    {},
                    'dummyAuditRef',
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('deleteMember test', () => {
        it('deleteMember test success', async () => {
            myDataService = {
                name: 'member',
                delete: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.deleteMember(
                'dummyDom',
                'dummyRole',
                'dummyMem',
                'dummyAuditRef',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('deleteMember test error', async () => {
            myDataServiceErr = {
                name: 'member',
                delete: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .deleteMember(
                    'dummyDom',
                    'dummyRole',
                    'dummyMem',
                    'dummyAuditRef',
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('deletePendingMember test', () => {
        it('deletePendingMember test success', async () => {
            myDataService = {
                name: 'member',
                delete: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.deletePendingMember(
                'dummyDom',
                'dummyRole',
                'dummyMem',
                'dummyAuditRef',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('deletePendingMember test error', async () => {
            myDataServiceErr = {
                name: 'member',
                delete: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .deletePendingMember(
                    'dummyDom',
                    'dummyRole',
                    'dummyMem',
                    'dummyAuditRef',
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getForm test', () => {
        it('getForm test success', async () => {
            myDataService = {
                name: 'get-form',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getForm();
            expect(result).toEqual(DATA);
        });
        it('getForm test error', async () => {
            myDataServiceErr = {
                name: 'get-form',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getForm().catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('searchDomains test', () => {
        it('searchDomains test success', async () => {
            myDataService = {
                name: 'search-domain',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.searchDomains('dummy');
            expect(result).toEqual(DATA);
        });
        it('searchDomains test error', async () => {
            myDataServiceErr = {
                name: 'search-domain',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.searchDomains().catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getServices test', () => {
        it('getServices test success', async () => {
            myDataService = {
                name: 'services',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getServices('dummy');
            expect(result).toEqual(DATA);
        });
        it('getServices test error', async () => {
            myDataServiceErr = {
                name: 'services',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getServices().catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getService test', () => {
        it('getService test success', async () => {
            myDataService = {
                name: 'service',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getService('dummy');
            expect(result).toEqual(DATA);
        });
        it('getService test error', async () => {
            myDataServiceErr = {
                name: 'service',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getService().catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('addService test', () => {
        it('addService test success', async () => {
            myDataService = {
                name: 'service',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.addService(
                'dummyDom',
                'dummyRole',
                'dummyMem',
                'https://dummy',
                'v0',
                '1234',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('addService test error', async () => {
            myDataServiceErr = {
                name: 'service',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .addService(
                    'dummyDom',
                    'dummyRole',
                    'dummyMem',
                    'https://dummy',
                    'v0',
                    '1234',
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('deleteService test', () => {
        it('deleteService test success', async () => {
            myDataService = {
                name: 'service',
                delete: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.deleteService('dummyDom', 'dummyRole', '1234');
            expect(result).toEqual(DATA);
        });
        it('deleteService test error', async () => {
            myDataServiceErr = {
                name: 'service',
                delete: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .deleteService('dummyDom', 'dummyRole', '1234')
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('addKey test', () => {
        it('addKey test success', async () => {
            myDataService = {
                name: 'key',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.addKey(
                'dummyDom',
                'dummyRole',
                'dummyMem',
                'https://dummy',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('addKey test error', async () => {
            myDataServiceErr = {
                name: 'key',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .addKey(
                    'dummyDom',
                    'dummyRole',
                    'dummyMem',
                    'https://dummy',
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('deleteKey test', () => {
        it('deleteKey test success', async () => {
            myDataService = {
                name: 'key',
                delete: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.deleteKey(
                'dummyDom',
                'dummyRole',
                '1234',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('deleteKey test error', async () => {
            myDataServiceErr = {
                name: 'key',
                delete: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .deleteKey('dummyDom', 'dummyRole', '1234', '1234')
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('allowProviderTemplate test', () => {
        it('allowProviderTemplate test success', async () => {
            myDataService = {
                name: 'provider',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.allowProviderTemplate(
                'dummyDom',
                'dummyRole',
                'dummyTemplate',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('allowProviderTemplate test error', async () => {
            myDataServiceErr = {
                name: 'provider',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .allowProviderTemplate(
                    'dummyDom',
                    'dummyRole',
                    'dummyTemplate',
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getStatus test', () => {
        it('getStatus test success', async () => {
            myDataService = {
                name: 'status',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getStatus();
            expect(result).toEqual(DATA);
        });
        it('getStatus test error', async () => {
            myDataServiceErr = {
                name: 'status',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getStatus().catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getPolicy test', () => {
        it('getPolicy test success', async () => {
            myDataService = {
                name: 'policy',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getPolicy('dummyDom', 'dummyPol');
            expect(result).toEqual(DATA);
        });
        it('getPolicy test error', async () => {
            myDataServiceErr = {
                name: 'policy',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getPolicy('dummyDom', 'dummyPol').catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getProvider test', () => {
        it('getProvider test success', async () => {
            myDataService = {
                name: 'provider',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getProvider('dummyDom', 'dummySvc');
            expect(result).toEqual(DATA);
        });
        it('getProvider test error', async () => {
            myDataServiceErr = {
                name: 'provider',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getProvider('dummyDom', 'dummySvc').catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getPolicies test', () => {
        it('getPolicies test success', async () => {
            myDataService = {
                name: 'policies',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getPolicies('dummyDom');
            expect(result).toEqual(DATA);
        });
        it('getPolicies test error', async () => {
            myDataServiceErr = {
                name: 'policies',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getPolicies('dummyDom').catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('addPolicy test', () => {
        it('addPolicy test success', async () => {
            myDataService = {
                name: 'policy',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.addPolicy(
                'dummyDom',
                'dummyPol',
                'dummyRole',
                'dummyResource',
                'get',
                'allow',
                true,
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('addPolicy test error', async () => {
            myDataServiceErr = {
                name: 'policy',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .addPolicy(
                    'dummyDom',
                    'dummyPol',
                    'dummyRole',
                    'dummyResource',
                    'get',
                    'allow',
                    true,
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('deletePolicy test', () => {
        it('deletePolicy test success', async () => {
            myDataService = {
                name: 'policy',
                delete: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.deletePolicy('dummyDom', 'dummyRole', '1234');
            expect(result).toEqual(DATA);
        });
        it('deletePolicy test error', async () => {
            myDataServiceErr = {
                name: 'policy',
                delete: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .deletePolicy('dummyDom', 'dummyRole', '1234')
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getHistory test', () => {
        it('getHistory test success', async () => {
            myDataService = {
                name: 'domain-history',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getHistory(
                'dummyDom',
                'ALL',
                '2020-01-01T00:00:00Z',
                '2020-01-01T00:00:00Z',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('getHistory test error', async () => {
            myDataServiceErr = {
                name: 'domain-history',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .getHistory(
                    'dummyDom',
                    'ALL',
                    '2020-01-01T00:00:00Z',
                    '2020-01-01T00:00:00Z',
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('addAssertion test', () => {
        it('addAssertion test success', async () => {
            myDataService = {
                name: 'assertion',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.addAssertion(
                'dummyDom',
                'dummyPol',
                'dummyRole',
                'dummyResource',
                'get',
                'allow',
                true,
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('addAssertion test error', async () => {
            myDataServiceErr = {
                name: 'assertion',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .addAssertion(
                    'dummyDom',
                    'dummyPol',
                    'dummyRole',
                    'dummyResource',
                    'get',
                    'allow',
                    true,
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('deleteAssertion test', () => {
        it('deleteAssertion test success', async () => {
            myDataService = {
                name: 'assertion',
                delete: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.deleteAssertion(
                'dummyDom',
                'dummyRole',
                'dummyAsser',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('deleteAssertion test error', async () => {
            myDataServiceErr = {
                name: 'assertion',
                delete: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .deleteAssertion('dummyDom', 'dummyRole', 'dummyAsser', '1234')
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('deleteSubDomain test', () => {
        it('deleteSubDomain test success', async () => {
            myDataService = {
                name: 'domain',
                delete: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.deleteSubDomain(
                'dummyDom',
                'dummyRole',
                'dummy',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('deleteSubDomain test error', async () => {
            myDataServiceErr = {
                name: 'domain',
                delete: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .deleteSubDomain('dummyDom', 'dummyRole', 'dummy', '1234')
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('putMeta test', () => {
        it('putMeta test success', async () => {
            myDataService = {
                name: 'role-meta',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.putMeta(
                'dummyDom',
                'dummyRole',
                {},
                'dummyRef',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('putMeta test error', async () => {
            myDataServiceErr = {
                name: 'meta',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .putMeta('dummyDom', 'dummyRole', {}, 'dummyRef', '1234')
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('isAWSTemplateApplied test', () => {
        it('isAWSTemplateApplied test success', async () => {
            myDataService = {
                name: 'domain-templates',
                read: function (req, resource, params, config, callback) {
                    callback(null, { templateNames: 'test' });
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.isAWSTemplateApplied('dummyDom');
            expect(result).toBeFalsy();
        });
        it('isAWSTemplateApplied test error', async () => {
            myDataServiceErr = {
                name: 'domain-templates',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.isAWSTemplateApplied('dummyDom').catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('applyAWSTemplates test', () => {
        it('applyAWSTemplates test success', async () => {
            myDataService = {
                name: 'domain-templates',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.applyAWSTemplates(
                'dummyDom',
                'dummyRef',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('applyAWSTemplates test error', async () => {
            myDataServiceErr = {
                name: 'domain-templates',
                create: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .applyAWSTemplates('dummyDom', 'dummyRef', '1234')
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getAuthOptions test', () => {
        it('getAuthOptions test success', async () => {
            myDataService = {
                name: 'auth-options',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getAuthOptions();
            expect(result).toEqual(DATA);
        });
        it('getAuthOptions test error', async () => {
            myDataServiceErr = {
                name: 'auth-options',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getAuthOptions().catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getHeaderDetails test', () => {
        it('getHeaderDetails test success', async () => {
            myDataService = {
                name: 'header-details',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getHeaderDetails();
            expect(result).toEqual(DATA);
        });
        it('getHeaderDetails test error', async () => {
            myDataServiceErr = {
                name: 'header-details',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getHeaderDetails().catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getServicePageConfig test', () => {
        it('getServicePageConfig test success', async () => {
            myDataService = {
                name: 'service-page-config',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getServicePageConfig();
            expect(result).toEqual(DATA);
        });
        it('getServicePageConfig test error', async () => {
            myDataServiceErr = {
                name: 'service-page-config',
                read: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api.getServicePageConfig().catch((err) => {
                expect(err).not.toBeNull();
            });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getDomainTemplateDetailsList test', () => {
        it('getDomainTemplateDetailsList test success', async () => {
            myDataService = {
                name: 'templates',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getDomainTemplateDetailsList({});
            expect(result).toEqual(DATA);
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('deleteTransportRule test', () => {
        it('deleteTransportRule test success', async () => {
            myDataService = {
                name: 'transport-rule',
                delete: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.deleteTransportRule(
                'dummyDom',
                'dummyPol',
                '123',
                'dummyRole',
                'dummyAuditRef',
                '1234'
            );
            expect(result).toEqual(DATA);
        });
        it('deleteTransportRule test error', async () => {
            myDataServiceErr = {
                name: 'transport-rule',
                delete: function (req, resource, params, config, callback) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .deleteTransportRule(
                    'dummyDom',
                    'dummyPol',
                    '123',
                    'dummyRole',
                    'dummyAuditRef',
                    '1234'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('validateMicrosegmentationPolicy test', () => {
        it('validateMicrosegmentationPolicy test success', async () => {
            myDataService = {
                name: 'validateMicrosegmentation',
                update: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.validateMicrosegmentationPolicy(
                'inbound',
                'dummyRoleMembers',
                'service1',
                'service2',
                '123-234',
                '1024'
            );
            expect(result).toEqual(DATA);
        });
        it('validateMicrosegmentationPolicy test error', async () => {
            myDataServiceErr = {
                name: 'validateMicrosegmentation',
                update: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .validateMicrosegmentationPolicy(
                    'inbound',
                    'dummyRoleMembers',
                    'service1',
                    'service2',
                    '123-234',
                    '1024'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('editMicrosegmentation test', () => {
        it('editMicrosegmentation test success', async () => {
            myDataService = {
                name: 'microsegmentation',
                update: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.editMicrosegmentation(
                'domain1',
                'false',
                'false',
                'true',
                'dummyData',
                '1024'
            );
            expect(result).toEqual(DATA);
        });
        it('editMicrosegmentation test error', async () => {
            myDataServiceErr = {
                name: 'microsegmentation',
                update: function (
                    req,
                    resource,
                    params,
                    body,
                    config,
                    callback
                ) {
                    return callback({}, null);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataServiceErr);
            await api
                .editMicrosegmentation(
                    'domain1',
                    'false',
                    'false',
                    'true',
                    'dummyData',
                    '1024'
                )
                .catch((err) => {
                    expect(err).not.toBeNull();
                });
        });
        afterEach(() => fetchrStub.restore());
    });
    describe('getResourceAccessList test', () => {
        it('getResourceAccessList test success', async () => {
            myDataService = {
                name: 'resource-access',
                read: function (req, resource, params, config, callback) {
                    callback(null, DATA);
                },
            };
            fetchrStub = sinon.stub(Fetchr, 'isRegistered');
            fetchrStub.returns(myDataService);
            result = await api.getResourceAccessList('dummy');
            expect(result).toEqual(DATA);
        });
    });
});
