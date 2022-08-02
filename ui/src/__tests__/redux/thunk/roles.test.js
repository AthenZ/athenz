import MockApi from '../../../mock/MockApi';
import sinon from 'sinon';
import { getExpiryTime } from '../../../redux/utils';
import { _ } from 'lodash';
import {
    loadingInProcess,
    loadingSuccess,
} from '../../../redux/actions/loading';
import {
    addMemberToRoles,
    deleteMemberFromAllRoles,
    deleteRole,
    getRole,
    getRoles,
} from '../../../redux/thunks/roles';
import {
    deleteRoleFromStore,
    loadRole,
    loadRoles,
    returnRoles,
} from '../../../redux/actions/roles';
import { storeRoles } from '../../../redux/actions/domains';
import {
    addMemberToStore,
    deleteMemberFromStore,
} from '../../../redux/actions/collections';

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
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadingInProcess('getRole')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadRole({ roleMembers: {} }, 'dom:role.role1')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(3).args[0],
                loadingSuccess('getRole')
            )
        ).toBeTruthy();
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
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockReturnValue({});
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                roles: { domainName: domainName },
            };
        };
        try {
            await deleteRole(
                'role1',
                'auditRef',
                'test'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
            expect(e.body.message).toBe('Role role1 doesnt exist');
        }

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
    });

    it('successfully delete role', async () => {
        jest.spyOn(roleSelector, 'thunkSelectRoles').mockReturnValue({
            'dom:role.role1': {},
        });
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
        MockApi.setMockApi({
            addMemberToRoles: jest.fn().mockReturnValue(Promise.resolve(true)),
        });
        const fakeDispatch = sinon.spy();

        await addMemberToRoles(
            domainName,
            ['role1', 'role2'],
            { memberName: 'member1' },
            'test'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                addMemberToStore(
                    { memberName: 'member1' },
                    'role',
                    'dom:role.role1'
                )
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                addMemberToStore(
                    { memberName: 'member1' },
                    'role',
                    'dom:role.role2'
                )
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

// TODO roy - test review role, add role
