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

var reqUtils = require('../utils/req');

module.exports = {
  addDomain: function(params, restClient, cb) {
    restClient.postDomain({
      auditRef: '',
      detail: {
        auditEnabled: params.auditEnabled,
        name: params.name,
        adminUsers: params.adminUsers,
        // zms_server requires product id
        ypmId: 0
      }
    }, cb);
  },
  deleteDomain: function(params, restClient, cb) {
    restClient.deleteTopLevelDomain({
      name: params.name
    }, cb);
  },
  addSubDomain: function(params, restClient, cb) {
    restClient.postSubDomain({
      parent: params.parent,
      detail: {
        parent: params.parent,
        name: params.name,
        adminUsers: params.adminUsers
      }
    }, cb);
  },
  deleteSubDomain: function(params, restClient, cb) {
    restClient.deleteSubDomain({
      parent: params.parent,
      name: params.name
    }, cb);
  },
  addUserDomain: function(params, restClient, cb) {
    restClient.postUserDomain({
      name: params.name,
      detail: {
        name: params.name
      }
    }, cb);
  },
  deleteUserDomain: function(params, restClient, cb) {
    restClient.deleteUserDomain({
      name: params.name
    }, cb);
  },
  fetchUserDomains: function(params, restClient, cb) {
    var apiCount = 2,
      userDomains = [],
      userAdminDomains = [],
      apiCb = function(count, err) {
        if(count === 0) {
          var data = userDomains.map(function(name) {
            return {
              name: name,
              type: reqUtils.getDomainDisplayLabel(reqUtils.ascertainDomainType(name).domainType),
              admin: userAdminDomains.indexOf(name) > -1
            };
          });
          cb(err, data);
        }
      };

    restClient.getDomainList({
      roleMember: params.userId
    },
    function(err, json) {
      if (!err && Array.isArray(json.names)) {
        userDomains = json.names;
      }
      apiCb(--apiCount, err);
    });

    restClient.getDomainList({
      roleMember: params.userId,
      roleName: 'admin'
    },
    function(err, json) {
      if (!err && Array.isArray(json.names)) {
        userAdminDomains = json.names;
      }
      apiCb(--apiCount, err);
    });
  },
  fetchAllDomains: function(params, restClient, cb) {
    restClient.getDomainList(params, function(err, json) {
      var output = [];
      if (!err && Array.isArray(json.names)) {
        output = json.names;
        return cb(null, output);
      }
      cb(err);
    });
  },
  fetchDomainMetadata: function(params, restClient, cb) {
    restClient.getDomain({
      domain: params.domainId
    }, function(err, data) {
      if(!err && data) {
        data.editUrl = `/athenz/domain/${data.name}/edit`;
      }
      cb(err, data);
    });
  }
};
