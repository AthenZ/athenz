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

var paginationUtils = require('../utils/pagination');
var viewUtils = require('../utils/view');
var reqUtils = require('../utils/req');
var config = require('../../config/config.js')();

function getModifyRoleMemberHandlerCb(inputRoles, cb) {
  var count = Array.isArray(inputRoles) ? inputRoles.length : 0;
  if (!count) {
    return cb('Roles is not an array', inputRoles);
  }

  var roles = {};
  return function(err) {
    var role = this;
    roles[role] = {
      error: false,
      msg: ''
    };
    if (err) {
      roles[role].error = true;
      roles[role].msg = reqUtils.getErrorMessage(err);
    }

    viewUtils.callCb(cb, roles, --count);
  };
}

module.exports = {
  fetchRoles: function(params, restClient, cb) {
    var pageParams = paginationUtils.populateQueryParams('all');
    restClient.getRoles({
      limit: pageParams.count,
      domainName: params.domainId
    }, function(err, json) {
      if (!err && json && Array.isArray(json.list)) {
        return cb(null, json.list);
      }
      cb(err);
    });
  },
  fetchRole: function(params, restClient, cb) {
    restClient.getRole({
      domainName: params.domainId,
      roleName: params.roleId
    }, function(err, roleData) {
      var members = [];
      if (!err && roleData && Array.isArray(roleData.members)) {
        members = roleData.members.map(function(member) {
          if (member.startsWith(config.userDomain + '.')){
            member = member.substring(config.userDomain.length + 1);
          }
          return member;
        });
        return cb(null, members);
      }
      cb(err, members);
    });
  },
  addMember: function(params, restClient, cb) {
    var roleCb = getModifyRoleMemberHandlerCb(params.roles, cb);
    if(typeof roleCb !== 'function') {
      return;
    }

    params.roles.forEach(function(role) {
      var fields = {
        domainName: params.domain,
        roleName: role,
        memberName: params.member,
        auditRef: '',
        membership: {
          memberName: params.member
        }
      };
      restClient.putMembership(fields, roleCb.bind(role));
    });
  },
  deleteMember: function(params, restClient, cb) {
    var roleCb = getModifyRoleMemberHandlerCb(params.roles, cb);
    if(typeof roleCb !== 'function') {
      return;
    }

    params.roles.forEach(function(role) {
      var fields = {
        domainName: params.domain,
        roleName: role,
        memberName: params.member,
        auditRef: ''
      };
      restClient.deleteMembership(fields, roleCb.bind(role));
    });
  }
};
