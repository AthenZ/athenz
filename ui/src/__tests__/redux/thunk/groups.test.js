import MockApi from '../../../mock/MockApi';
import sinon from 'sinon';
import { getExpiryTime } from '../../../redux/utils';
import { _ } from 'lodash';
import {
    loadingInProcess,
    loadingSuccess,
} from '../../../redux/actions/loading';
import {
    deleteGroup,
    getDomainRoleMembers,
    getGroup,
    getGroups,
} from '../../../redux/thunks/groups';
import {
    deleteGroupFromStore,
    loadGroup,
    loadGroupRoleMembers,
    loadGroups,
    returnGroups,
} from '../../../redux/actions/groups';
import { storeGroups } from '../../../redux/actions/domains';

const groupsThunk = require('../../../redux/thunks/groups');
const groupSelector = require('../../../redux/selectors/group');
const domainName = 'dom';
const utils = require('../../../redux/utils');

describe('getGroups method', () => {
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

    it('test getGroups no data in the store', async () => {
        const getState = () => {
            return { groups: {} };
        };
        MockApi.setMockApi({
            getGroups: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getGroups(domainName)(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getGroups')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadGroups({}, domainName, getExpiryTime())
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getGroups')
            )
        ).toBeTruthy();
    });

    it('test getGroups dom exists in the store asked for dom and its not expired', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(false);
        const getState = () => {
            return { groups: { domainName, expiry: getExpiryTime() } };
        };
        const fakeDispatch = sinon.spy();
        await getGroups(domainName)(fakeDispatch, getState);
        expect(
            _.isEqual(fakeDispatch.getCall(0).args[0], returnGroups())
        ).toBeTruthy();
    });

    it('test getGroups dom exists in the store asked for dom but expired', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(true);
        const getState = () => {
            return { groups: { domainName, expiry: getExpiryTime() } };
        };
        MockApi.setMockApi({
            getGroups: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getGroups(domainName)(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getGroups')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadGroups({}, domainName, getExpiryTime())
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getGroups')
            )
        ).toBeTruthy();
    });

    it('test getGroups dom exists in the store asked for newDomain which not in the store', async () => {
        const groupsData = {
            domainName,
            expiry: getExpiryTime(),
            groups: {},
        };
        const getState = () => {
            return {
                groups: groupsData,
                domains: {},
            };
        };
        MockApi.setMockApi({
            getGroups: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getGroups('newDomain')(fakeDispatch, getState);

        expect(
            _.isEqual(fakeDispatch.getCall(0).args[0], storeGroups(groupsData))
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadingInProcess('getGroups')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadGroups({}, 'newDomain', getExpiryTime())
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(3).args[0],
                loadingSuccess('getGroups')
            )
        ).toBeTruthy();
    });

    it('test getGroups dom exists in the store asked for newDomain which already in the store', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(false);
        const groupsData = {
            domainName,
            expiry: getExpiryTime(),
            groups: {},
        };
        const groups = {
            groups: {},
            domainName: 'newDomain',
            expiry: getExpiryTime(),
        };
        const getState = () => {
            return {
                groups: groupsData,
                domains: { newDomain: { groups } },
            };
        };
        const fakeDispatch = sinon.spy();
        await getGroups('newDomain')(fakeDispatch, getState);

        expect(
            _.isEqual(fakeDispatch.getCall(0).args[0], storeGroups(groupsData))
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadGroups({}, 'newDomain', groups.expiry)
            )
        ).toBeTruthy();
    });
});

describe('getGroup method', () => {
    beforeAll(() => {
        jest.spyOn(groupsThunk, 'getGroups').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(groupsThunk, 'getGroups').mockRestore();
        jest.spyOn(groupSelector, 'thunkSelectGroup').mockRestore();
    });

    afterEach(() => {
        MockApi.cleanMockApi();
        jest.spyOn(utils, 'isExpired').mockRestore();
    });

    it('test getGroup the group auditLog exists', async () => {
        jest.spyOn(groupSelector, 'thunkSelectGroup').mockReturnValue({
            auditLog: [],
        });
        const fakeDispatch = sinon.spy();

        await getGroup(domainName, 'group1')(fakeDispatch, () => {});
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(1).args[0], returnGroups())
        ).toBeTruthy();
    });

    it('test getGroup the group auditLog not exists', async () => {
        jest.spyOn(groupSelector, 'thunkSelectGroup').mockReturnValue({});
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            getGroup: jest.fn().mockReturnValue(Promise.resolve({})),
        });
        await getGroup(domainName, 'group1')(fakeDispatch, () => {});
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadingInProcess('getGroup')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadGroup({ groupMembers: {} }, 'dom:group.group1')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(3).args[0],
                loadingSuccess('getGroup')
            )
        ).toBeTruthy();
    });
});

describe('deleteGroup method', () => {
    beforeAll(() => {
        jest.spyOn(groupsThunk, 'getGroups').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(groupsThunk, 'getGroups').mockRestore();
        jest.spyOn(groupSelector, 'thunkSelectGroups').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('get an error because groupName doesnt exists', async () => {
        jest.spyOn(groupSelector, 'thunkSelectGroups').mockReturnValue({});
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                groups: { domainName: domainName },
            };
        };
        try {
            await deleteGroup(
                'group1',
                'auditRef',
                'test'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
            expect(e.body.message).toBe('Group group1 doesnt exist');
        }

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
    });

    it('successfully delete group', async () => {
        jest.spyOn(groupSelector, 'thunkSelectGroups').mockReturnValue({
            'dom:group.group1': {},
        });
        const getState = () => {
            return {
                groups: { domainName: domainName },
            };
        };
        MockApi.setMockApi({
            deleteGroup: jest.fn().mockReturnValue(Promise.resolve(true)),
        });
        const fakeDispatch = sinon.spy();

        await deleteGroup('group1', 'auditRef', 'test')(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                deleteGroupFromStore('dom:group.group1')
            )
        ).toBeTruthy();
    });
});

describe('getDomainRoleMembers method', () => {
    const groupsThunkUtils = require('../../../redux/thunks/utils/groups');
    beforeAll(() => {
        jest.spyOn(groupsThunk, 'getGroups').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(groupsThunk, 'getGroups').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('successfully add member to groups', async () => {
        const getState = () => {
            return {};
        };
        MockApi.setMockApi({
            getDomainRoleMembers: jest
                .fn()
                .mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();

        await getDomainRoleMembers(domainName, 'group1')(
            fakeDispatch,
            getState
        );

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadingInProcess('getDomainRoleMembers')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadGroupRoleMembers('dom:group.group1', [])
            )
        ).toBeTruthy();
    });
});

// TODO roy - test review group, add group
