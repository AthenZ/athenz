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

module.exports = {
    Crypto: require('./src/util/Crypto'),
    KeyStore: require('./src/impl/KeyStore'),
    PrincipalAuthority: require('./src/impl/PrincipalAuthority'),
    PrincipalToken: require('./src/token/PrincipalToken'),
    RoleAuthority: require('./src/impl/RoleAuthority'),
    RoleToken: require('./src/token/RoleToken'),
    SimplePrincipal: require('./src/impl/SimplePrincipal'),
    SimpleServiceIdentityProvider: require('./src/impl/SimpleServiceIdentityProvider'),
    Validate: require('./src/util/Validate'),
    YBase64: require('./src/util/YBase64'),
};
