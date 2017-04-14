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
 *
 *
 * Contains util functions which pertain to overall page rendering and common
 * callback functions
 */
'use strict';

var _ = require('lodash');
var config = require('../../config/config.js')();

module.exports = {
  /**
   * Call response.render() based on pending parallel API calls
   */
  render: function(res, viewName, viewData, pendingApiCount) {
    if(pendingApiCount === 0) {
      res.render(viewName, viewData);
    }
  },
  callCb: function(cb, output, pendingApiCount) {
    if(pendingApiCount === 0) {
      cb(null, output);
    }
  },
  highlightCurrent: function(list, id, idIndex) {
    idIndex = idIndex || 'id';

    var currentIndex = _.findIndex(list, function(item) {
      return item[idIndex] === id;
    });

    if(currentIndex >= 0) {
      var current = list[currentIndex];
      current.highlight = 'highlight';
      list.splice(currentIndex, 1);
      list.unshift(current);
    }

    return list;
  },
  getShortName: function(name, type) {
    var key = `${type}.`;
    return name && name.includes(key) ? name.substr(name.indexOf(key) + key.length) : name;
  },
  getRoleType: function(role) {
    return  role.trust ? 'Delegated' : 'Regular';
  },
  getMemberDetail: function(member) {
    var detail = {
      name: member
    };

    if (member.startsWith(config.userDomain + '.')) {
      detail.userlink = config.userLink(member.substring(config.userDomain.length + 1));
    }
    return detail;
  },
  populateRoleData: function(role) {
    var roleName = this.getShortName(role.name, 'role');
    role.fullName = role.name;
    role.name = roleName;
    role.deleteUrl = `/athenz/domain/${role.domainId}/role/${roleName}/delete`;
    role.type = this.getRoleType(role);
    if (role.members) {
      // Fill user links
      role.members = role.members.map(this.getMemberDetail);
    }
    if (Array.isArray(role.auditLog)) {
      role.auditLog.reverse();
      // Fill user links
      role.auditLog = role.auditLog.map(function(entry) {
        return {
          action: entry.action,
          admin: this.getMemberDetail(entry.admin),
          created: entry.created,
          member: this.getMemberDetail(entry.member)
        };
      }, this);
    }
    return role;
  },
  populateServiceData: function(service) {
    var serviceName = this.getShortName(service.name, service.domainId);
    service.fullName = service.name;
    service.name = serviceName;
    service.deleteUrl = `/athenz/domain/${service.domainId}/service/${serviceName}/delete`;
    service.addKeyUrl = `/athenz/domain/${service.domainId}/service/${serviceName}/key/add`;
    service.user = service.user || null;
    return service;
  },
  populatePolicyData: function(policy) {
    policy.fullName = policy.name;
    policy.name = this.getShortName(policy.name, 'policy');
    policy.deleteUrl = `/athenz/domain/${policy.domainId}/policy/${policy.name}/delete`;
    policy.addAssertion = `/athenz/domain/${policy.domainId}/policy/${policy.name}/assertion/add`;
    return policy;
  },
  moveRole: function(roles, name) {
    var index = roles.findIndex(role => role.name === name);
    if (index !== -1) {
      var r = roles.splice(index, 1);
      roles.unshift(r[0]);
    }
    return roles;
  }
};
