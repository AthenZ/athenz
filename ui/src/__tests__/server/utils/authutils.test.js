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

const authUtils = require('../../../server/utils/authUtils');

describe('authUtils test', () => {
    test('should redirect on err', () => {
        let res = {};
        res.redirect = jest.fn();
        let err = new Error();
        authUtils.postAuth({}, res, {}, err);
        expect(res.redirect).toHaveBeenCalled();
    });
    test('should clear cookies on flag', () => {
        let req = {
            clearCookie: true,
        };
        let res = {};
        res.clearCookie = jest.fn();
        authUtils.postAuth(req, res, { cookieName: 'a' });
        expect(res.clearCookie).toHaveBeenCalled();
    });
    test('should clear cookies on flag', () => {
        let req = {
            authSvcToken: 'dummy',
            cookies: [],
        };
        let res = {};
        res.cookie = jest.fn();
        authUtils.postAuth(req, res, { cookieName: 'a', cookieMaxAge: 60 });
        expect(res.cookie).toHaveBeenCalled();
    });
});
