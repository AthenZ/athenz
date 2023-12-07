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
    addGroup,
    deleteGroup,
    getGroup,
    getGroups,
    reviewGroup,
    getReviewGroups,
} from '../../../redux/thunks/groups';
import {
    addGroupToStore,
    deleteGroupFromStore,
    loadGroup,
    loadGroupRoleMembers,
    loadGroups,
    loadGroupsToReview,
    returnGroups,
    reviewGroupToStore,
} from '../../../redux/actions/groups';
import { storeGroups } from '../../../redux/actions/domains';
import {
    configStoreGroups,
    singleApiGroup,
    singleStoreGroup,
} from '../config/group.test';
import AppUtils from '../../../components/utils/AppUtils';

const groupsThunk = require('../../../redux/thunks/groups');
const groupSelector = require('../../../redux/selectors/groups');
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
    it('test getGroups should fail to get from server', async () => {
        const getState = () => {
            return { groups: {} };
        };
        const err = { statusCode: 400, body: { massage: 'failed' } };
        MockApi.setMockApi({
            getGroups: jest.fn().mockReturnValue(Promise.reject(err)),
        });

        const fakeDispatch = sinon.spy();
        try {
            await getGroups(domainName)(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(_.isEqual(e, err)).toBeTruthy();
            expect(
                _.isEqual(
                    fakeDispatch.getCall(0).args[0],
                    loadingInProcess('getGroups')
                )
            ).toBeTruthy();
            expect(
                _.isEqual(
                    fakeDispatch.getCall(1).args[0],
                    loadingFailed('getGroups', err)
                )
            ).toBeTruthy();
        }
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
            getDomainRoleMembers: jest
                .fn()
                .mockReturnValue(Promise.resolve({})),
        });
        await getGroup(domainName, 'group1')(fakeDispatch, () => {});
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadingInProcess('getGroup')
            )
        ).toBeTruthy();
        expect(fakeDispatch.getCall(2).args[0]).toEqual(
            loadGroup(
                {
                    auditLog: [],
                    groupMembers: {},
                    groupPendingMembers: {},
                    roleMembers: {},
                },
                'dom:group.group1'
            )
        );
        expect(
            _.isEqual(
                fakeDispatch.getCall(3).args[0],
                loadingSuccess('getGroup')
            )
        ).toBeTruthy();
    });
});

describe('addGroup method', () => {
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

    it('get an error because groupName already exists', async () => {
        jest.spyOn(groupSelector, 'thunkSelectGroups').mockReturnValue(
            AppUtils.deepClone(configStoreGroups)
        );
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                groups: { domainName: domainName },
            };
        };
        try {
            await addGroup(
                'group1',
                'auditRef',
                { name: 'group1' },
                'csrf'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(409);
            expect(e.body.message).toBe('Group group1 already exists');
        }

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
    });

    it('successfully add group', async () => {
        jest.spyOn(groupSelector, 'thunkSelectGroups').mockReturnValue(
            AppUtils.deepClone(configStoreGroups)
        );
        const getState = () => {
            return {
                groups: {
                    domainName: domainName,
                    groups: AppUtils.deepClone(configStoreGroups),
                },
            };
        };
        MockApi.setMockApi({
            addGroup: jest
                .fn()
                .mockReturnValue(
                    Promise.resolve(AppUtils.deepClone(singleApiGroup))
                ),
        });
        const fakeDispatch = sinon.spy();

        await addGroup(
            'singlegroup',
            'auditRef',
            { name: 'singlegroup' },
            'csrf'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            addGroupToStore(AppUtils.deepClone(singleStoreGroup))
        );
    });
    it('successfully add group with upper case and add it as lower case', async () => {
        jest.spyOn(groupSelector, 'thunkSelectGroups').mockReturnValue(
            AppUtils.deepClone(configStoreGroups)
        );
        const getState = () => {
            return {
                groups: {
                    domainName: domainName,
                    groups: AppUtils.deepClone(configStoreGroups),
                },
            };
        };
        MockApi.setMockApi({
            addGroup: jest
                .fn()
                .mockReturnValue(
                    Promise.resolve(AppUtils.deepClone(singleApiGroup))
                ),
        });
        const fakeDispatch = sinon.spy();

        await addGroup(
            'SingleGroup',
            'auditRef',
            { name: 'SingleGroup' },
            'csrf'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            addGroupToStore(AppUtils.deepClone(singleStoreGroup))
        );
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

describe('reviewGroup method', () => {
    beforeAll(() => {
        jest.spyOn(groupsThunk, 'getGroups').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(groupsThunk, 'getGroups').mockRestore();
        jest.spyOn(groupSelector, 'thunkSelectGroups').mockRestore();
        jest.spyOn(groupSelector, 'selectUserReviewGroups').mockRestore();
        jest.spyOn(groupsThunk, 'getGroups').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('successfully review group', async () => {
        jest.spyOn(groupsThunk, 'getGroup').mockReturnValue(true);
        jest.spyOn(groupSelector, 'thunkSelectGroups').mockReturnValue(
            AppUtils.deepClone(configStoreGroups)
        );
        const getState = () => {
            return {
                groups: {
                    domainName: domainName,
                    groups: AppUtils.deepClone(configStoreGroups),
                },
            };
        };
        jest.spyOn(groupSelector, 'selectUserReviewGroups').mockReturnValue([]);
        MockApi.setMockApi({
            reviewGroup: jest
                .fn()
                .mockReturnValue(
                    Promise.resolve(AppUtils.deepClone(singleApiGroup))
                ),
        });
        const fakeDispatch = sinon.spy();

        await reviewGroup(
            'singlegroup',
            { name: 'singlegroup' },
            'auditRef',
            'csrf'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            reviewGroupToStore(singleStoreGroup.name, singleStoreGroup)
        );
    });
});

describe('getReviewGroups', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('should getReviewGroups no data in the store', async () => {
        const getState = () => {
            return { groups: {} };
        };

        MockApi.setMockApi({
            getReviewGroups: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getReviewGroups()(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getReviewGroups')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(1).args[0], loadGroupsToReview([]))
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getReviewGroups')
            )
        ).toBeTruthy();
    });

    it('should getReviewGroups success', async () => {
        const getState = () => {
            return { groups: {} };
        };

        let mockResponse = [
            {
                domainName: 'home.jtsang01',
                name: 'heyreviewthis',
                memberExpiryDays: 10,
                memberReviewDays: 0,
                serviceExpiryDays: 10,
                serviceReviewDays: 0,
                groupExpiryDays: 0,
                groupReviewDays: 0,
            },
        ];
        MockApi.setMockApi({
            getReviewGroups: jest
                .fn()
                .mockReturnValue(Promise.resolve(mockResponse)),
        });
        const fakeDispatch = sinon.spy();
        await getReviewGroups()(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getReviewGroups')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadGroupsToReview(mockResponse)
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getReviewGroups')
            )
        ).toBeTruthy();
    });
});
