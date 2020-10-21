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
const routes = require('next-routes');

module.exports = routes()
    // these are in src/pages/*.js
    .add('home', '/')
    .add('old-home', '/athenz')
    .add('login', '/login')
    .add('create-domain', '/domain/create')
    .add('manage-domains', '/domain/manage')
    .add('role', '/domain/:domain/role')
    .add('old-role', '/athenz/domain/:domain/role')
    .add('workflow', '/workflow')
    .add('old-workflow', '/athenz/workflow')
    .add('search', '/search/:type/:searchterm')
    .add('service', '/domain/:domain/service')
    .add('template', '/domain/:domain/template')
    .add('history', '/domain/:domain/history')
    .add('members', '/domain/:domain/role/:role/members')
    .add('review', '/domain/:domain/role/:role/review')
    .add('role-policy', '/domain/:domain/role/:role/policy')
    .add('policy', '/domain/:domain/policy')
    .add('settings', '/domain/:domain/role/:role/settings')
    .add('role-history', '/domain/:domain/role/:role/history');
