/*
 * Copyright 2020 Verizon Media
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

const errorHandler = require('../../../server/utils/errorHandler');

describe('server errorHandler test', () => {
    test('should convert Fetchr error into native error', () => {
        let err = {
            status: 404,
            message: 'test err',
        };
        let errResp = errorHandler.fetcherError(err);
        expect(errResp).not.toBeNull();
        expect(errResp.statusCode).toEqual(404);
    });
    test('should convert Fetchr error into native error with message', () => {
        let err = {
            status: 403,
            message: {
                message: 'err msg'
            },
        };
        let errResp = errorHandler.fetcherError(err);
        expect(errResp).not.toBeNull();
        expect(errResp.statusCode).toEqual(403);
        expect(errResp.output.message).toEqual('err msg');
    });
    test('should handle blank error message', () => {
        let err = {
            status: 403,
        };
        let errResp = errorHandler.fetcherError(err);
        expect(errResp).not.toBeNull();
        expect(errResp.statusCode).toEqual(403);
        expect(errResp.output.message).toEqual('');
    });
});
