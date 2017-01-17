/**
 * Copyright 2016 Yahoo Inc.
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

module.exports = {
  STATUSES: {
    DOMAIN_ALREADY_EXISTS: '${ domainType } domain ${ domain } already exists',
    CREDENTIAL_ERROR: 'Credential error. Please report issue to athenz-ui admin. Thank you.',
    DOMAIN_SUCCESSFULLY_CREATED: 'Congratulations! Your ${ domainType } domain ${ domain } has successfully been created.',
    DOMAIN_SUCCESSFULLY_DELETED: 'Successfully deleted domain ${ domain }',
    SERVICE_SUCCESSFULLY_DELETED: 'Successfully deleted service ${ service }',
    SERVICE_SUCCESSFULLY_CREATED: 'Successfully created service ${ service }'
  },
  AUDIT: [{
    key: 'audit_enabled',
    value: 'Audit Enabled',
  }],
  ENTITY_MAPPING: {
    role: 'Role',
    service: 'Service',
    policy: 'Policy'
  },
  ENTITY_ID_MAPPING: {
    role: 'ROLE',
    service: 'SERVICE',
    policy: 'POLICY'
  },
  ROLE_CATEGORIES: [{
    key: 'group',
    value: 'Regular',
    default: true
  }, {
    key: 'delegated',
    value: 'Delegated'
  }],
  POLICY_TYPES: [{
    key: 'ALLOW',
    value: 'Allow',
    default: true
  }, {
    key: 'DENY',
    value: 'Deny'
  }]
};
