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

import sinon from 'sinon';

describe('userService test', () => {
    let sandbox;
    let userService;
    let userServiceImpl;

    // re-setting userService before each test
    beforeEach(() => {
        jest.resetModules();
        sandbox = sinon.createSandbox();
        userService = require('../../../server/services/userService');
        userServiceImpl = require('../../../server/services/userServiceImpl');
    });

    test('should be able to refresh user data', () => {
        let metadata = {
            ContentLength: 100,
        };
        sandbox
            .stub(userServiceImpl, 'checkUsersUpdate')
            .returns(Promise.resolve(metadata));
        let userData = [
            {
                is_human: 1,
                login: 'testuser',
                gecos: 'full name',
                enabled_status: 1,
            },
        ];
        sandbox
            .stub(userServiceImpl, 'fetchUpdatedUsers')
            .returns(Promise.resolve(JSON.stringify(userData)));
        userService
            .refreshUserData({
                userFilePath: 'data',
                userFileName: 'users_data.json',
                userDomains: 'user,unix',
            })
            .then(() => {
                expect(userService.getUserFullName('user.testuser')).toEqual(
                    'full name'
                );
            });
    });

    test('refreshUserData - repeated call should change userArray', async () => {
        const userData1 = [
            {
                is_human: 1,
                enabled_status: 1,
                login: 'testuser1',
                gecos: 'full name1',
            },
            {
                is_human: 1,
                enabled_status: 1,
                login: 'testuser2',
                gecos: 'full name2',
            },
        ];

        const userData2 = [
            {
                is_human: 1,
                enabled_status: 1,
                login: 'testuser1',
                gecos: 'full name1',
            },
        ];

        let metadata1 = {
            ContentLength: 100,
        };
        let metadata2 = {
            ContentLength: 50,
        };

        // imitating data change after first call
        const checkUsersUpdateStub = sandbox
            .stub(userServiceImpl, 'checkUsersUpdate')
            .onFirstCall()
            .returns(Promise.resolve(metadata1))
            .onSecondCall()
            .returns(Promise.resolve(metadata2));
        const fetchUpdatedUsersStub = sandbox
            .stub(userServiceImpl, 'fetchUpdatedUsers')
            .onFirstCall()
            .returns(Promise.resolve(JSON.stringify(userData1)))
            .onSecondCall()
            .returns(Promise.resolve(JSON.stringify(userData2)));

        // first call - will get json with 2 users on
        const call1 = userService.refreshUserData({
            userFilePath: 'data',
            userFileName: 'users_data.json',
            userDomains: 'user,unix',
        });
        await Promise.all([call1]);
        // check 2 users were stored
        expect(userService.getAllUsers().length).toEqual(2);

        // second call
        const call2 = userService.refreshUserData({
            userFilePath: 'data',
            userFileName: 'users_data.json',
            userDomains: 'user,unix',
        });
        await Promise.all([call2]);
        // should return 1 user this time
        expect(userService.getAllUsers().length).toEqual(1);

        // verify call count to avoid test succeeding without making any calls
        expect(checkUsersUpdateStub.callCount).toEqual(2);
        expect(fetchUpdatedUsersStub.callCount).toEqual(2);
    });
});
