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

var pageUtils = require('../utils/page');
var viewUtils = require('../utils/view');
var reqUtils = require('../utils/req');

module.exports = {
  addRole: function(req, res) {
    pageUtils.initCommonData(req, res);
    var params = {
      domainName: req.params.domainId,
      roleName: req.body.name,
      role: {
        name: req.params.domainId + ':role.' + req.body.name,
        members: req.body.members ? req.body.members.split(',') : [],
        trust: req.body['delegated-domain']
      }
    };
    params.role.members = params.role.members.map(member => member.trim());
    req.restClient.putRole(params, reqUtils.ajaxHtmlHandler(res, function() {
      var role = {
        domainId: req.params.domainId,
        name: params.roleName,
        modified: new Date(),
        members: params.role.members,
        active: 'active'
      };

      viewUtils.populateRoleData(role);

      res.render('rolerow', {
        layout: false,
        roles: [role]
      });
    }));
  },
  deleteRole: function(req, res) {
    var params = {
      domainName: req.params.domainId,
      roleName: req.params.role
    };
    req.restClient.deleteRole(params, reqUtils.ajaxJsonHandler(res));
  },
  getRoleRow: function(req, res) {
    pageUtils.initCommonData(req, res);
    var params = {
      domainName: req.params.domainId,
      roleName: req.params.role,
      expand: true,
      auditLog: true
    };

    req.restClient.getRole(params, reqUtils.ajaxHtmlHandler(res, function(role) {
      role.active = 'active';
      role.domainId = req.params.domainId;
      viewUtils.populateRoleData(role);

      res.render('rolerow', {
        layout: false,
        roles: [role]
      });
    }));
  }
};
