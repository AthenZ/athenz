/**
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

class IdentityMock {
    constructor(domain, name) {
        this._domain = domain;
        this._name = name;

        this._creds = null;
        if (domain && name) {
            this._creds = 'v=S1;d=' + domain + ';n=' + name + ';';
        }
    }

    getDomain() {
        return this._domain;
    }

    getName() {
        return this._name;
    }

    getCredentials() {
        return this._creds;
    }

    getAuthority() {
        if (!this._domain) {
            return null;
        }
        return this;
    }

    getHeader() {
        return 'Athenz-Principal-Auth';
    }
}

module.exports = IdentityMock;
