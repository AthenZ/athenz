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

const userService = require('../../../server/services/userService');
const userServiceImpl = require('../../../server/services/userServiceImpl');
const sinon = require('sinon');

describe('userService test', () => {
    let sandbox = sinon.createSandbox();
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
});
