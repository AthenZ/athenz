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
import MockApi from '../../../mock/MockApi';
import sinon from 'sinon';
import { getExpiryTime } from '../../../redux/utils';
import { _ } from 'lodash';
import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../../../redux/actions/loading';
import {
    addMemberToRoles,
    addRole,
    deleteMemberFromAllRoles,
    deleteRole,
    getRole,
    getRoles,
    reviewRole,
    getReviewRoles,
} from '../../../redux/thunks/roles';
import {
    addRoleToStore,
    deleteRoleFromStore,
    loadRole,
    loadRoles,
    returnRoles,
    reviewRoleToStore,
    loadRolesToReview,
} from '../../../redux/actions/roles';
import { storeRoles } from '../../../redux/actions/domains';
import {
    addMemberToStore,
    deleteMemberFromStore,
} from '../../../redux/actions/collections';
import {
    singleApiRole,
    singleStoreRole,
    configStoreRoles,
    configRole1,
    singleMember,
} from '../config/role.test';
import AppUtils from '../../../components/utils/AppUtils';
import { expiry, modified } from '../../config/config.test';

const rolesThunk = require('../../../redux/thunks/roles');
const roleSelector = require('../../../redux/selectors/roles');
const domainName = 'dom';
const utils = require('../../../redux/utils');

describe('test roles thunk', () => {
    beforeAll(() => {
        jest.spyOn(utils, 'getExpiryTime').mockReturnValue(5);
    });

    afterAll(() => {
        jest.spyOn(utils, 'getExpiryTime').mockRestore();
    });

    afterEach(() => {
        MockApi.cleanMockApi();
        jest.spyOn(utils, 'isExpired').mockRestore();
    });

    it('test getRoles no data in the store', async () => {
        const getState = () => {
            return { roles: {} };
        };
        MockApi.setMockApi({
            getRoles: jest.fn().mockReturnValue(Promise.resolve([])),
            getRoleMembers: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getRoles(domainName)(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getRoles')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadRoles({}, domainName, getExpiryTime())
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getRoles')
            )
        ).toBeTruthy();
    });

    it('test getRoles dom exists in the store asked for dom and its not expired', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(false);
        const getState = () => {
            return { roles: { domainName, expiry: getExpiryTime() } };
        };
        const fakeDispatch = sinon.spy();
        await getRoles(domainName)(fakeDispatch, getState);
        expect(
            _.isEqual(fakeDispatch.getCall(0).args[0], returnRoles())
        ).toBeTruthy();
    });

    it('test getRoles dom exists in the store asked for dom but expired', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(true);
        const getState = () => {
            return { roles: { domainName, expiry: getExpiryTime() } };
        };
        MockApi.setMockApi({
            getRoles: jest.fn().mockReturnValue(Promise.resolve([])),
            getRoleMembers: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getRoles(domainName)(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getRoles')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadRoles({}, domainName, getExpiryTime())
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getRoles')
            )
        ).toBeTruthy();
    });

    it('test getRoles dom exists in the store asked for newDomain which not in the store', async () => {
        const rolesData = {
            domainName,
            expiry: getExpiryTime(),
            roles: {},
        };
        const getState = () => {
            return {
                roles: rolesData,
                domains: {},
            };
        };
        MockApi.setMockApi({
            getRoles: jest.fn().mockReturnValue(Promise.resolve([])),
            getRoleMembers: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getRoles('newDomain')(fakeDispatch, getState);

        expect(
            _.isEqual(fakeDispatch.getCall(0).args[0], storeRoles(rolesData))
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadingInProcess('getRoles')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadRoles({}, 'newDomain', getExpiryTime())
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(3).args[0],
                loadingSuccess('getRoles')
            )
        ).toBeTruthy();
    });

    it('test getRoles dom exists in the store asked for newDomain which already in the store', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(false);
        const rolesData = {
            domainName,
            expiry: getExpiryTime(),
            roles: {},
        };
        const roles = {
            roles: {},
            domainName: 'newDomain',
            expiry: getExpiryTime(),
        };
        const getState = () => {
            return {
                roles: rolesData,
                domains: { newDomain: { roles } },
            };
        };
        const fakeDispatch = sinon.spy();
        await getRoles('newDomain')(fakeDispatch, getState);

        expect(
            _.isEqual(fakeDispatch.getCall(0).args[0], storeRoles(rolesData))
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadRoles({}, 'newDomain', roles.expiry)
            )
        ).toBeTruthy();
    });
    it('test getRoles should fail to get from server', async () => {
        const getState = () => {
            return { roles: {} };
        };
        const err = { statusCode: 400, body: { massage: 'failed' } };
        MockApi.setMockApi({
            getRoles: jest.fn().mockReturnValue(Promise.reject(err)),
            getRoleMembers: jest.fn().mockReturnValue(Promise.resolve([])),
        });

        const fakeDispatch = sinon.spy();
        try {
            await getRoles(domainName)(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(_.isEqual(e, err)).toBeTruthy();
            expect(
                _.isEqual(
                    fakeDispatch.getCall(0).args[0],
                    loadingInProcess('getRoles')
                )
            ).toBeTruthy();
            expect(
                _.isEqual(
                    fakeDispatch.getCall(1).args[0],
                    loadingFailed('getRoles', err)
                )
            ).toBeTruthy();
        }
    });
});

describe('getRole method', () => {
    beforeAll(() => {
        jest.spyOn(rolesThunk, 'getRoles').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(rolesThunk, 'getRoles').mockRestore();
        jest.spyOn(roleSelector, 'thunkSelectRole').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('test getRole the role auditLog exists', async () => {
        jest.spyOn(roleSelector, 'thunkSelectRole').mockReturnValue({
            auditLog: [],
        });
        const fakeDispatch = sinon.spy();

        await getRole(domainName, 'role1')(fakeDispatch, () => {});
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(1).args[0], returnRoles())
        ).toBeTruthy();
    });

    it('test getRole the role auditLog not exists', async () => {
        jest.spyOn(roleSelector, 'thunkSelectRole').mockReturnValue({});
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            getRole: jest.fn().mockReturnValue(Promise.resolve({})),
        });
        await getRole(domainName, 'role1')(fakeDispatch, () => {});
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            loadingInProcess('getRole')
        );
        expect(fakeDispatch.getCall(2).args[0]).toEqual(
            loadRole(
                { roleMembers: {}, rolePendingMembers: {}, auditLog: [] },
                'dom:role.role1'
            )
        );
        expect(fakeDispatch.getCall(3).args[0]).toEqual(
            loadingSuccess('getRole')
        );
    });
});

describe('addRole method', () => {
    beforeAll(() => {
        jest.spyOn(rolesThunk, 'getRoles').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(rolesThunk, 'getRoles').mockRestore();
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockRestore();
    });

    it('successfully add role', async () => {
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockReturnValue(
            configStoreRoles
        );
        const getState = () => {
            return {
                roles: { domainName: domainName },
            };
        };

        MockApi.setMockApi({
            addRole: jest
                .fn()
                .mockReturnValue(
                    Promise.resolve(AppUtils.deepClone(singleApiRole))
                ),
        });

        const fakeDispatch = sinon.spy();

        await addRole(
            'role2',
            'auditRef',
            { name: 'singlerole' },
            'csrf'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();

        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                addRoleToStore(singleStoreRole)
            )
        ).toBeTruthy();
    });

    it('get an error because roleName already exists', async () => {
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockReturnValue(
            configStoreRoles
        );
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                roles: { domainName: domainName },
            };
        };
        try {
            await addRole(
                'role1',
                'auditRef',
                configRole1,
                'csrf'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(409);
            expect(e.body.message).toBe('Role role1 already exists');
        }

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
    });

    it('successfully override existing role ', async () => {
        const storeRole = {
            name: 'dom:role.role1',
            modified: modified,
            roleMembers: {
                'user.user1': {
                    memberName: 'user.user1',
                    expiration: expiry,
                    approved: true,
                    auditRef: 'Updated domain Meta using Athenz UI',
                    memberFullName: null,
                },
            },
            rolePendingMembers: {},
        };
        const apiRole = {
            name: 'dom:role.role1',
            modified: modified,
            roleMembers: [
                {
                    memberName: 'user.user1',
                    expiration: expiry,
                    approved: true,
                    auditRef: 'Updated domain Meta using Athenz UI',
                    memberFullName: null,
                },
            ],
        };
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockReturnValue({
            'dom:role.role1': {},
        });
        MockApi.setMockApi({
            addRole: jest
                .fn()
                .mockReturnValue(Promise.resolve(AppUtils.deepClone(apiRole))),
        });
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                roles: { domainName: domainName },
            };
        };
        await addRole(
            'role1',
            'auditRef',
            storeRole,
            'csrf',
            true
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();

        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                addRoleToStore(storeRole)
            )
        ).toBeTruthy();
    });

    it('add role with convert UpperCase to lower case', async () => {
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockReturnValue(
            configStoreRoles
        );

        const getState = () => {
            return {
                roles: { domainName: domainName },
            };
        };

        MockApi.setMockApi({
            addRole: jest
                .fn()
                .mockReturnValue(
                    Promise.resolve(AppUtils.deepClone(singleApiRole))
                ),
        });

        const fakeDispatch = sinon.spy();

        await addRole(
            'SingleRole',
            'auditRef',
            { name: 'dom:role.SingleRole' },
            'csrf'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        let mychange = fakeDispatch.getCall(1).args[0];
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            addRoleToStore(singleStoreRole)
        );
    });
});

describe('deleteRole method', () => {
    beforeAll(() => {
        jest.spyOn(rolesThunk, 'getRoles').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(rolesThunk, 'getRoles').mockRestore();
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('get an error because roleName doesnt exists', async () => {
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockReturnValue(
            configStoreRoles
        );
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                roles: { domainName: domainName },
            };
        };
        try {
            await deleteRole(
                'singlerole',
                'auditRef',
                'test'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
            expect(e.body.message).toBe('Role singlerole doesnt exist');
        }

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
    });

    it('successfully delete role', async () => {
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockReturnValue(
            configStoreRoles
        );
        const getState = () => {
            return {
                roles: { domainName: domainName },
            };
        };
        MockApi.setMockApi({
            deleteRole: jest.fn().mockReturnValue(Promise.resolve(true)),
        });
        const fakeDispatch = sinon.spy();

        await deleteRole('role1', 'auditRef', 'test')(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                deleteRoleFromStore('dom:role.role1')
            )
        ).toBeTruthy();
    });
});

describe('AddMemberToRoles method', () => {
    const rolesThunkUtils = require('../../../redux/thunks/utils/roles');
    beforeAll(() => {
        jest.spyOn(rolesThunk, 'getRoles').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(rolesThunk, 'getRoles').mockRestore();
        jest.spyOn(rolesThunkUtils, 'checkIfMemberInAllRoles').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('get an error because all members are in the role', async () => {
        jest.spyOn(rolesThunkUtils, 'checkIfMemberInAllRoles').mockReturnValue(
            true
        );
        const fakeDispatch = sinon.spy();
        const getState = () => {};

        try {
            await addMemberToRoles(
                domainName,
                ['role1', 'role2'],
                { memberName: 'member1' },
                'test'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(409);
            expect(e.body.message).toBe('member1 is already in all roles');
        }

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
    });

    it('successfully add member to roles', async () => {
        jest.spyOn(rolesThunkUtils, 'checkIfMemberInAllRoles').mockReturnValue(
            false
        );
        const getState = () => {
            return {
                roles: { domainName: domainName },
            };
        };
        const member1 = {
            roleName: 'dom:role.role1',
            memberName: 'user.user10',
            expiration: expiry,
            approved: true,
            auditRef: 'Updated domain Meta using Athenz UI',
            memberFullName: null,
        };
        const member2 = {
            roleName: 'dom:role.admin',
            memberName: 'user.user10',
            expiration: expiry,
            approved: true,
            auditRef: 'Updated domain Meta using Athenz UI',
            memberFullName: null,
        };
        MockApi.setMockApi({
            addMemberToRoles: jest
                .fn()
                .mockReturnValue(Promise.resolve([member1, member2])),
        });
        const fakeDispatch = sinon.spy();
        await addMemberToRoles(
            domainName,
            ['Role1', 'Admin'],
            { memberName: 'user.user10' },
            'test'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                addMemberToStore(member1, 'role', 'dom:role.role1')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                addMemberToStore(member2, 'role', 'dom:role.admin')
            )
        ).toBeTruthy();
    });
});

describe('deleteMemberFromAllRoles method', () => {
    afterAll(() => {
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('successfully delete member from all roles', async () => {
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockReturnValue({
            'dom:role.role1': { roleMembers: { member1: {} } },
            'dom:role.role2': { roleMembers: { member2: {} } },
            'dom:role.role3': { roleMembers: { member1: {} } },
        });
        const getState = () => {};
        MockApi.setMockApi({
            deleteRoleMember: jest.fn().mockReturnValue(Promise.resolve(true)),
        });
        const fakeDispatch = sinon.spy();

        await deleteMemberFromAllRoles(
            domainName,
            'member1',
            'test',
            'user'
        )(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                deleteMemberFromStore('member1', 'role', 'dom:role.role1')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                deleteMemberFromStore('member1', 'role', 'dom:role.role3')
            )
        ).toBeTruthy();
    });
});

describe('reviewRole method', () => {
    beforeAll(() => {
        jest.spyOn(rolesThunk, 'getRole').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(rolesThunk, 'getRole').mockRestore();
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockRestore();
        jest.spyOn(roleSelector, 'selectUserReviewRoles').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('successfully reviewed role', async () => {
        const fakeDispatch = sinon.spy();
        const getState = () => {};

        jest.spyOn(roleSelector, 'selectUserReviewRoles').mockReturnValue([]);
        MockApi.setMockApi({
            reviewRole: jest
                .fn()
                .mockReturnValue(
                    Promise.resolve(AppUtils.deepClone(singleApiRole))
                ),
        });
        await reviewRole(
            'dom',
            { name: 'role1' },
            'test',
            'csrf'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            reviewRoleToStore(singleStoreRole.name, singleStoreRole)
        );
    });
});

describe('getReviewRoles', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('should getReviewRoles no data in the store', async () => {
        const getState = () => {
            return { roles: {} };
        };

        MockApi.setMockApi({
            getReviewRoles: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getReviewRoles()(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getReviewRoles')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(1).args[0], loadRolesToReview([]))
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getReviewRoles')
            )
        ).toBeTruthy();
    });

    it('should getReviewRoles success', async () => {
        const getState = () => {
            return { roles: {} };
        };

        let mockResponse = [
            {
                domainName: 'home.jtsang01',
                name: 'rolereviewtest',
                memberExpiryDays: 10,
                memberReviewDays: 10,
                serviceExpiryDays: 0,
                serviceReviewDays: 0,
                groupExpiryDays: 10,
                groupReviewDays: 10,
            },
            {
                domainName: 'home.jtsang01',
                name: 't',
                memberExpiryDays: 5,
                memberReviewDays: 5,
                serviceExpiryDays: 5,
                serviceReviewDays: 5,
                groupExpiryDays: 5,
                groupReviewDays: 5,
            },
        ];
        MockApi.setMockApi({
            getReviewRoles: jest
                .fn()
                .mockReturnValue(Promise.resolve(mockResponse)),
        });
        const fakeDispatch = sinon.spy();
        await getReviewRoles()(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getReviewRoles')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadRolesToReview(mockResponse)
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getReviewRoles')
            )
        ).toBeTruthy();
    });
});
