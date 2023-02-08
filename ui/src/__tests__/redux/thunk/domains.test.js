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
import {
    createSubDomain,
    createUserDomain,
    deleteSubDomain,
    getAllDomainsList,
    getBusinessServicesAll,
    getPendingDomainMembersListByDomain,
    getUserDomainsList,
    processPendingMembers,
} from '../../../redux/thunks/domains';
import { _ } from 'lodash';
import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../../../redux/actions/loading';
import {
    addDomainToUserDomainsList,
    deleteDomainFromUserDomainList,
    loadAllDomainsList,
    loadBusinessServicesAll,
    loadPendingDomainMembersList,
    loadUserDomainList,
    processGroupPendingMembersToStore,
    processRolePendingMembersToStore,
    returnBusinessServicesAll,
    returnDomainList,
} from '../../../redux/actions/domains';
import {
    apiBusinessServicesAll,
    storeBusinessServicesAll,
} from '../../config/config.test';
import { getFullName } from '../../../redux/utils';
import { subDomainDelimiter } from '../../../redux/config';

const userDomains = [
    { name: 'userDomain1', adminDomain: true },
    { name: 'UserDomain2', adminDomain: false },
];
const domainsSelectors = require('../../../redux/selectors/domains');

describe('test getUserDomainsList thunk', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should return user domain list', async () => {
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                domains: { domainsList: userDomains },
            };
        };

        await getUserDomainsList()(fakeDispatch, getState);

        expect(
            _.isEqual(fakeDispatch.getCall(0).args[0], returnDomainList())
        ).toBeTruthy();
    });
    it('should load user domain list', async () => {
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                domains: {},
            };
        };
        MockApi.setMockApi({
            listUserDomains: jest
                .fn()
                .mockReturnValue(Promise.resolve(userDomains)),
        });

        await getUserDomainsList()(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getUserDomainsList')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadUserDomainList(userDomains)
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getUserDomainsList')
            )
        ).toBeTruthy();
    });
});

describe('test getBusinessServicesAll thunk', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should success return BusinessServicesAll', async () => {
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                domains: { businessServicesAll: storeBusinessServicesAll },
            };
        };
        await getBusinessServicesAll()(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                returnBusinessServicesAll()
            )
        ).toBeTruthy();
    });
    it('should success load BusinessServicesAll', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            getMeta: jest.fn().mockReturnValue(apiBusinessServicesAll),
        });
        const getState = () => {
            return {
                domains: {},
            };
        };
        await getBusinessServicesAll()(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadBusinessServicesAll(storeBusinessServicesAll)
            )
        ).toBeTruthy();
    });
});

describe('test createSubDomain thunk', () => {
    const parentDomain = 'dom';
    const subDomain = 'test';
    const adminUser = 'user1';
    const getState = () => {};
    afterEach(() => {
        MockApi.cleanMockApi();
        jest.spyOn(domainsSelectors, 'selectPersonalDomain').mockRestore();
    });
    it('should success create sub-domain', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(domainsSelectors, 'selectPersonalDomain').mockReturnValue(
            null
        );
        MockApi.setMockApi({
            createSubDomain: jest.fn().mockReturnValue(Promise.resolve()),
        });
        await createSubDomain(
            parentDomain,
            subDomain,
            adminUser
        )(fakeDispatch, getState);
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                addDomainToUserDomainsList(
                    getFullName(parentDomain, subDomainDelimiter, subDomain)
                )
            )
        ).toBeTruthy();
    });
    it('sub-domain already exists, should throw error', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(domainsSelectors, 'selectPersonalDomain').mockReturnValue({
            name: getFullName(parentDomain, subDomainDelimiter, subDomain),
        });
        try {
            await createSubDomain(
                parentDomain,
                subDomain,
                adminUser
            )(fakeDispatch, getState);
        } catch (e) {
            expect(e.statusCode).toBe(409);
        }
    });
});

describe('test createUserDomain thunk', () => {
    const userId = 'userId';
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should success to create user-domain', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            createUserDomain: jest.fn().mockReturnValue(Promise.resolve()),
        });
        await createUserDomain(userId)(fakeDispatch);
        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                addDomainToUserDomainsList('home.' + userId)
            )
        ).toBeTruthy();
    });
    it('should fail to create user-domain', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            createUserDomain: jest
                .fn()
                .mockReturnValue(Promise.reject('failed')),
        });
        try {
            await createUserDomain(userId)(fakeDispatch);
            fail();
        } catch (e) {
            expect(e).toBe('failed');
        }
    });
});

describe('test deleteSubDomain thunk', () => {
    const parentDomain = 'dom';
    const subDomain = 'test';
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should success to delete sub-domain', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            deleteSubDomain: jest.fn().mockReturnValue(Promise.resolve()),
        });
        await deleteSubDomain(parentDomain, subDomain)(fakeDispatch);
        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                deleteDomainFromUserDomainList(
                    getFullName(parentDomain, subDomainDelimiter, subDomain)
                )
            )
        ).toBeTruthy();
    });
    it('should fail to create delete sub-domain', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            deleteSubDomain: jest
                .fn()
                .mockReturnValue(Promise.reject('failed')),
        });
        try {
            await deleteSubDomain(parentDomain, subDomain)(fakeDispatch);
            fail();
        } catch (e) {
            expect(e).toBe('failed');
        }
    });
});

describe('test getAllDomainsList thunk', () => {
    const allDomainList = [
        {
            name: 'sys.test',
            value: 'sys.test',
        },
        {
            name: 'sys.redux',
            value: 'sys.redux',
        },
        {
            name: 'sys.yahoo',
            value: 'sys.yahoo',
        },
        {
            name: 'sys.yahoo.sport',
            value: 'sys.yahoo.sport',
        },
    ];
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should success load all domain list', async () => {
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                domains: {},
            };
        };
        MockApi.setMockApi({
            listAllDomains: jest
                .fn()
                .mockReturnValue(Promise.resolve(allDomainList)),
        });

        await getAllDomainsList()(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getAllDomainsList')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadAllDomainsList(allDomainList)
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getAllDomainsList')
            )
        ).toBeTruthy();
    });
    it('should success load all domain list', async () => {
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                domains: {},
            };
        };
        MockApi.setMockApi({
            listAllDomains: jest.fn().mockReturnValue(Promise.reject('failed')),
        });
        try {
            await getAllDomainsList()(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e).toBe('failed');
            expect(
                _.isEqual(
                    fakeDispatch.getCall(0).args[0],
                    loadingInProcess('getAllDomainsList')
                )
            ).toBeTruthy();
            expect(
                _.isEqual(
                    fakeDispatch.getCall(1).args[0],
                    loadingFailed('getAllDomainsList')
                )
            ).toBeTruthy();
        }
    });
});

const pendingMembers = {
    'domuser.user1role1': {
        category: 'role',
        domainName: 'dom',
        memberName: 'user.user1',
        memberNameFull: null,
        roleName: 'role1',
        userComment: 'added using Athenz UI',
        auditRef: '',
        requestPrincipal: 'user.user2',
        requestPrincipalFull: null,
        requestTime: '2022-07-12T14:29:08.384Z',
        expiryDate: '2022-09-25T14:29:08.374Z',
    },
    'domuser.user3role2': {
        category: 'role',
        domainName: 'dom',
        memberName: 'user.user3',
        memberNameFull: null,
        roleName: 'role2',
        userComment: 'added using Athenz UI',
        auditRef: '',
        requestPrincipal: 'user.user2',
        requestPrincipalFull: null,
        requestTime: '2022-07-12T13:14:57.267Z',
        expiryDate: '2022-09-25T13:14:57.257Z',
    },
};

describe('test getPendingDomainMembersListByDomain thunk', () => {
    const getState = () => {};
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should success load pendingDomainMembersListByDomain', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            getPendingDomainMembersListByDomain: jest
                .fn()
                .mockReturnValue(Promise.resolve(pendingMembers)),
        });
        await getPendingDomainMembersListByDomain('dom')(
            fakeDispatch,
            getState
        );
        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getPendingDomainMembersListByDomain')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadPendingDomainMembersList(pendingMembers, 'dom')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getPendingDomainMembersListByDomain')
            )
        ).toBeTruthy();
    });
    it('should fail load pendingDomainMembersListByDomain', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            getPendingDomainMembersListByDomain: jest
                .fn()
                .mockReturnValue(Promise.reject('failed')),
        });
        try {
            await getPendingDomainMembersListByDomain('dom')(
                fakeDispatch,
                getState
            );
            fail();
        } catch (e) {
            expect(e).toBe('failed');
            expect(
                _.isEqual(
                    fakeDispatch.getCall(0).args[0],
                    loadingInProcess('getPendingDomainMembersListByDomain')
                )
            ).toBeTruthy();
            expect(
                _.isEqual(
                    fakeDispatch.getCall(1).args[0],
                    loadingFailed('getPendingDomainMembersListByDomain')
                )
            ).toBeTruthy();
        }
    });
});

const membership = {
    member: { memberName: 'user.user1' },
    domainName: 'dom',
    roleName: 'role1',
};

describe('test processPendingMembers thunk', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should success process role pending members', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            processPending: jest.fn().mockReturnValue(Promise.resolve()),
        });
        await processPendingMembers(
            'dom',
            'role1',
            'user.user1',
            '',
            'role',
            membership
        )(fakeDispatch);
        expect(fakeDispatch.getCall(0).args[0]).toEqual(
            processRolePendingMembersToStore('dom', 'role1', membership)
        );
    });
    it('should success process group pending members', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            processPending: jest.fn().mockReturnValue(Promise.resolve()),
        });
        await processPendingMembers(
            'dom',
            'group1',
            'user.user1',
            '',
            'group',
            membership
        )(fakeDispatch);
        expect(fakeDispatch.getCall(0).args[0]).toEqual(
            processGroupPendingMembersToStore('dom', 'group1', membership)
        );
    });
    it('should fail processPendingMembers', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            processPending: jest.fn().mockReturnValue(Promise.reject('failed')),
        });
        try {
            await processPendingMembers(
                'dom',
                'role1',
                'user.user1',
                '',
                'role',
                membership
            )(fakeDispatch);
            fail();
        } catch (e) {
            expect(e).toBe('failed');
        }
    });
});
