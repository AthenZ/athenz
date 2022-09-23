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

const publicKeyStore = require('../../../server/handlers/PublicKeyStore');
const sinon = require('sinon');
const fs = require('fs');
const auth_core = jest.requireActual('@athenz/auth-core');
const YBase64 = auth_core.YBase64;

describe('PublicKeyStore handler test', () => {
    test('should be able to get zms key correctly', () => {
        let fsStub = sinon.stub(fs, 'readFileSync');
        fsStub.returns(
            JSON.stringify({
                zmsPublicKeys: [
                    {
                        id: '0',
                        key: 'dummypublickey',
                    },
                ],
            })
        );
        const result = publicKeyStore.getPublicKey('sys.auth', 'zms', '0');
        expect(result).toEqual(YBase64.ybase64Decode('dummypublickey'));
        fsStub.restore();
    });
    test('should be able to get ui key correctly', () => {
        let fsStub = sinon.stub(fs, 'readFileSync');
        fsStub.returns('dummypublickey');
        const result = publicKeyStore.getPublicKey('athenz', 'unit-test', '1');
        expect(result).toEqual('dummypublickey');
        fsStub.restore();
    });
});
