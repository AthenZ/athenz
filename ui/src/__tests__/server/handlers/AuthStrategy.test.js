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

const config = require('../../../config/config')();
jest.mock('fs');
jest.mock('@athenz/auth-core');

const MOCK_FILE_INFO = {
    'keys/athenz.unit-test.pem':
        '-----BEGIN RSA PRIVATE KEY-----\n' +
        'MIIEowIBAAKCAQEAwTcE1vkGLw1fpsmJX1snyktMfhCJi73yDnNMPxp07Fh4r4ta\n' +
        '/N+5WOI4Xmmu9RoJ+ttwecdHZl/vHiJYUx+g8gRMqDrW8NjLbzEBLjSeB7eQ2RBs\n' +
        'OlL7dSjzYlPy3T/ZX32gbs9Cg/XzZifGl9TyaOOLZKkBAGb5goR+5D5enlgQvtr+\n' +
        'szsdaPLfalKoQfgdFyiRvLks4sPuHKo9kzc9dE487VFLI0k7gR0z4t2329DPC18r\n' +
        '8nrA01UcLu3Uaf83pzoqEU1GneSMyp8J44a/dWgjYbdU3V0/VA6iuWVmHWRiAKX5\n' +
        'nxrT2HsrkVZ6WOlFYwwualhoHHKw3Eo28LuXLQIDAQABAoIBAQCe9cL3kf0ybNBL\n' +
        'CfgJCZfc6MJP3Q8sduNUXCtYp02WvNrdocsDzJRSuhsiIdSdNgUL68nHhtoJMdgq\n' +
        'dJsyGA1zz3G53l7D27jTDAAqoYN6Wd3Dl61S9r6Gj2Bdfy+KM2OFGngJcl8I7iqH\n' +
        '2yWZ+MpO3RXrhNecGxwf8x3qbh2uKtrmcxP29sa5nKRs8HYtuvr/KQWRJnasvxqp\n' +
        'YV0HAse+3S2Pn40kGeNbunMAGbkGzSByswoTDVnxzYILu2BY9XUrFJyhHUgyaeVq\n' +
        'wsGHaPZAOfSvsKFOq6mJ9agsEH+9kFe+KAzLmr8apWMlokAH0DFmk569B+1dE5Jm\n' +
        'MMIdWz7JAoGBAPASQM1UdJGquo2xy0ioqAUI8MsrfxWZeXdGprq45X7bLm61udjL\n' +
        'F89ceUViXa+F5GVTKWnrc19C2VTgn3Xoe7StqAxsKrOqURQB4jOsrfgK8CnWE/pH\n' +
        'c0HP/LF0G9X84uLsx30IfUe7gmH++XQhZQBQlzeFNobGz1kBYCpruz2TAoGBAM4I\n' +
        '4jLEEwb/fQMsNpFH0EQk83L+OIGHujvYW+zwchftgoq52eBYv5j+fJsMox/CcSGZ\n' +
        'WcqLevq/LW23NcitkO3A9Q4StWwCnfwNZtS92QIrv0tOjeD+cLeXAjxRbe7nv5pW\n' +
        'hZTe+fLVTc4f+oZfjOLmWmN/H8x6DObwxLDJ4NA/AoGAKecVtoEqQ46oNzk0QT9m\n' +
        '7FIOLXgvG2cJY39KdMb3D7hUF3DSuntgcYozhJ/RuGRHZEQqs1ksbxEs+/qk+qCU\n' +
        'jwnMjjaHEYsF0dcuU1StnODT4ImEPSghfvg9o/+fKC+WroMjorhLnayl6lLl2ZZG\n' +
        'mdJ3QnKW/NlQsblivqTFLs8CgYA5jN2yFHbEI6VFt5neZtLT1gZyfnRGKiVpBfxX\n' +
        'aKpV6K/oFBW5xtBt6dfgb105R9TV78HXA7LsS25jESPi1CiBYL6SmcM3UlvSxeON\n' +
        'VSJCqvmaDW0wBaJyhanIM26jpvQsJjLV7Jqgq9g51VDjK9lsn69rz1yQfx8Pev1V\n' +
        '7G3xfQKBgDCtbgVIsKsrp6SgxRm8qLdGaiNoNz/TH3fRGKM6ONh/uV11xnVu9SLN\n' +
        'KoyRVAguStTHWF1e0dW0vmaMgq5F2NzDWnZwSgHw6NK0s/Tmxv1WMDV+k79Tqy24\n' +
        'zq2H3Y5fLcERdDEPvVgr53tiCv8Idj4VyVfNXfGdboiUKuLEucCQ\n' +
        '-----END RSA PRIVATE KEY-----',
};

describe('AuthStrategy Test', () => {
    beforeEach(() => {
        // Set up some mocked out file info before each test
        require('fs').__setMockFiles(MOCK_FILE_INFO);
    });
    test('should be able to create Strategy object', () => {
        const AuthStrategy = require('../../../server/handlers/AuthStrategy');
        let authStrategy = new AuthStrategy({}, config, {});
        expect(authStrategy).not.toBeNull();
        expect(authStrategy.authKey).not.toBeNull();
    });
    test('should clear cookies on login', () => {
        const AuthStrategy = require('../../../server/handlers/AuthStrategy');
        let authStrategy = new AuthStrategy({}, config, {});
        expect(authStrategy).not.toBeNull();
        const req = {
            cookies: [],
            headers: [],
            originalUrl: '/login',
        };
        authStrategy.authenticate(req);
        expect(req.clearCookie).toBeTruthy();
    });
    test('should create authSvcToken from cookie', () => {
        const AuthStrategy = require('../../../server/handlers/AuthStrategy');
        let authStrategy = new AuthStrategy({}, config, {});
        expect(authStrategy).not.toBeNull();
        const req = {
            cookies: {
                'Athenz-Principal-Auth': 'aa',
            },
            headers: [],
            session: {},
            originalUrl: '/dummy',
        };
        authStrategy.authenticate(req);
        expect(req.clearCookie).toBeFalsy();
        expect(req.authSvcToken).toEqual('aa');
    });
    test('should create authSvcToken from header', () => {
        const AuthStrategy = require('../../../server/handlers/AuthStrategy');
        let authStrategy = new AuthStrategy({}, config, {});
        expect(authStrategy).not.toBeNull();
        const req = {
            cookies: [],
            headers: {
                token: 'v=1;d=athenz;n=unit-test;',
            },
            session: {},
            originalUrl: '/dummy',
        };
        authStrategy.authenticate(req);
        expect(req.clearCookie).toBeFalsy();
        expect(req.authSvcToken).not.toBeNull();
    });
});
