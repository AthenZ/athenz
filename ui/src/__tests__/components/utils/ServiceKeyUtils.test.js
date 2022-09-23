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
import React from 'react';
import ServiceKeyUtils from '../../../components/utils/ServiceKeyUtils';

describe('ServiceKeyUtils', () => {
    it('should test', () => {
        let testkey =
            '-----BEGIN PUBLIC KEY-----\n' +
            'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyI+t1VxFMoIFPaxyVGww\n' +
            'MH++Mp5nt/oeiUSp5gksIrOh4pF2KKpROqGV+c8+W1gPyyl2jZBllhBzB3NCv97N\n' +
            'GHQGO3vbnPEraeR9P78Hglj4Vy3rUJX5YJlBE0cf8aZB3Sw3pqfQlR0t2UzUSw1d\n' +
            'kF6ROhFqjEqztBKdwHYugK8GgFAfn/KNxoycx3bCLXuwLSy0jbQ6pPDLtU8E/zCW\n' +
            '4dFulvnDh3UG6crSFghCT4X0Zp+20QGjhgQXojFXJPipCz5kzW107hCxiOiTO/u7\n' +
            'pMPslEWmlQ9eyrhdXOnxPWjO0kdyxW+GfilC+U3F8ZH5Dwg8UoZfdi3u+m1LLe1P\n' +
            'dQIDAQAB\n' +
            '-----END PUBLIC KEY-----';
        let trimkey = ServiceKeyUtils.trimKey(testkey);
        expect(trimkey).toEqual(
            '-----BEGIN PUBLIC KEY-----\n' +
                'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyI+t1VxFMoIFPaxyVGww\n' +
                'MH++Mp5nt/oeiUSp5gksIrOh4pF2KKpROqGV+c8+W1gPyyl2jZBllhBzB3NCv97N\n' +
                'GHQGO3vbnPEraeR9P78Hglj4Vy3rUJX5YJlBE0cf8aZB3Sw3pqfQlR0t2UzUSw1d\n' +
                'kF6ROhFqjEqztBKdwHYugK8GgFAfn/KNxoycx3bCLXuwLSy0jbQ6pPDLtU8E/zCW\n' +
                '4dFulvnDh3UG6crSFghCT4X0Zp+20QGjhgQXojFXJPipCz5kzW107hCxiOiTO/u7\n' +
                'pMPslEWmlQ9eyrhdXOnxPWjO0kdyxW+GfilC+U3F8ZH5Dwg8UoZfdi3u+m1LLe1P\n' +
                'dQIDAQAB\n' +
                '-----END PUBLIC KEY-----'
        );
        let encodekey = ServiceKeyUtils.y64Encode(testkey);
        expect(encodekey).toEqual(
            'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF5SSt0MVZ4Rk1vSUZQYXh5Vkd3dwpNSCsrTXA1bnQvb2VpVVNwNWdrc0lyT2g0cEYyS0twUk9xR1YrYzgrVzFnUHl5bDJqWkJsbGhCekIzTkN2OTdOCkdIUUdPM3ZiblBFcmFlUjlQNzhIZ2xqNFZ5M3JVSlg1WUpsQkUwY2Y4YVpCM1N3M3BxZlFsUjB0MlV6VVN3MWQKa0Y2Uk9oRnFqRXF6dEJLZHdIWXVnSzhHZ0ZBZm4vS054b3ljeDNiQ0xYdXdMU3kwamJRNnBQREx0VThFL3pDVwo0ZEZ1bHZuRGgzVUc2Y3JTRmdoQ1Q0WDBacCsyMFFHamhnUVhvakZYSlBpcEN6NWt6VzEwN2hDeGlPaVRPL3U3CnBNUHNsRVdtbFE5ZXlyaGRYT254UFdqTzBrZHl4VytHZmlsQytVM0Y4Wkg1RHdnOFVvWmZkaTN1K20xTExlMVAKZFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t'
        );
        let decodekey = ServiceKeyUtils.y64Decode(encodekey);
        expect(decodekey).toEqual(
            '-----BEGIN PUBLIC KEY-----\n' +
                'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyI+t1VxFMoIFPaxyVGww\n' +
                'MH++Mp5nt/oeiUSp5gksIrOh4pF2KKpROqGV+c8+W1gPyyl2jZBllhBzB3NCv97N\n' +
                'GHQGO3vbnPEraeR9P78Hglj4Vy3rUJX5YJlBE0cf8aZB3Sw3pqfQlR0t2UzUSw1d\n' +
                'kF6ROhFqjEqztBKdwHYugK8GgFAfn/KNxoycx3bCLXuwLSy0jbQ6pPDLtU8E/zCW\n' +
                '4dFulvnDh3UG6crSFghCT4X0Zp+20QGjhgQXojFXJPipCz5kzW107hCxiOiTO/u7\n' +
                'pMPslEWmlQ9eyrhdXOnxPWjO0kdyxW+GfilC+U3F8ZH5Dwg8UoZfdi3u+m1LLe1P\n' +
                'dQIDAQAB\n' +
                '-----END PUBLIC KEY-----'
        );
    });
});
