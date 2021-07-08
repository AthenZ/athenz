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

var identityMock = require('./IdentityMock');

class SiaProviderMock {
    constructor(domain, service) {
        this._domain = null;
        this._service = null;

        if (domain) {
            this._domain = domain.toString().toLowerCase();
        }
        if (service) {
            this._service = service.toString().toLowerCase();
        }
    }

    getIdentity(domain, service) {
        if (domain !== this._domain || service !== this._service) {
            return null;
        }
        return new identityMock(this._domain, this._service);
    }
}

module.exports = SiaProviderMock;
