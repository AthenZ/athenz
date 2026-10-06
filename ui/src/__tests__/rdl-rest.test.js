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
jest.mock('axios');
const axios = require('axios');
const rdlRest = require('../rdl-rest');

// transport errors from the http client carry the full request config,
// including forwarded cookies and the client certificate's private key
const transportError = (response) => {
    const err = new Error(
        'Client network socket disconnected before secure TLS connection was established'
    );
    err.code = 'ECONNRESET';
    err.config = {
        headers: { Cookie: 'okta_at=secret-okta-access-token' },
        httpsAgent: {
            options: {
                key: '-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----',
            },
        },
    };
    err.request = { socket: {} };
    if (response) {
        err.response = response;
    }
    return err;
};

const zmsClient = () =>
    rdlRest({
        apiHost: 'https://zms.example.com:4443/zms/v1',
        rdl: require('../config/zms.json'),
    })({ headers: {}, originalUrl: '/', query: {} });

describe('rdl-rest', () => {
    afterEach(() => {
        jest.resetAllMocks();
    });

    it('should not expose the request config of a transport error', (done) => {
        axios.request.mockRejectedValue(transportError());
        zmsClient().getDomain({ domain: 'athenz' }, (err, json) => {
            expect(json).toBeNull();
            expect(err.status).toBeUndefined();
            expect(err.error).toEqual({
                name: 'Error',
                code: 'ECONNRESET',
                message:
                    'Client network socket disconnected before secure TLS connection was established',
            });
            const logged = JSON.stringify(err);
            expect(logged).not.toContain('okta_at');
            expect(logged).not.toContain('PRIVATE KEY');
            done();
        });
    });

    it('should keep the status and server message of an error response', (done) => {
        axios.request.mockRejectedValue(
            transportError({
                status: 404,
                data: { code: 404, message: 'Domain not found' },
            })
        );
        zmsClient().getDomain({ domain: 'athenz' }, (err) => {
            expect(err.status).toEqual(404);
            expect(err.message).toEqual({
                code: 404,
                message: 'Domain not found',
            });
            const logged = JSON.stringify(err);
            expect(logged).not.toContain('okta_at');
            expect(logged).not.toContain('PRIVATE KEY');
            done();
        });
    });

    it('should return the response body on success', (done) => {
        axios.request.mockResolvedValue({
            status: 200,
            data: { name: 'athenz' },
        });
        zmsClient().getDomain({ domain: 'athenz' }, (err, json) => {
            expect(err).toBeNull();
            expect(json).toEqual({ name: 'athenz' });
            done();
        });
    });
});
