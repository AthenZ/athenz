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

var url = require('url');
var _ = require('lodash');

var cleanupFields = ['addError', 'addWgError', 'addPolicyError', 'requestId',
    'missing', 'failed', 'success', 'search', 'createdRole', 'createdResource', 'createdPolicy',
    'createdTransport', 'addWg', 'reviewWlError', 'workloadDelete', 'editWlError',
    'deleteError', 'changeOwnershipError'];

var MESSAGES = {
  changeOwnershipError: 'Failed to update domain ownership detail. Please contact support.',
  createdPolicy: 'New Policy Created',
  reviewWlError: 'Failed to update Workload status, Please try again',
  editWlError: 'Failed to edit Workload, Please try again',
  workloadDelete: 'Workload deleted from Workload Group',
  addWg: 'Workload Group added to ${ entity }',
  createdRole: 'New ${ entity } created. You can now start adding Workload Groups and Policies to it',
  createdResource: 'New ${ entity } created. You can now start adding Workload Groups and Transports to it',
  createdTransport: 'New Transport added to ${ entity }'
};

module.exports = {
  getCurrentSection: function(params) {
    var section = {};
    if (params.domainId) {
      section.title = 'Domain';
      section.id = params.domainId;
    }

    if(params.roleId) {
      section.title = 'Role';
      section.id = params.roleId;
      section.type = 'role';
    } else if (params.serviceId) {
      section.title = 'Service';
      section.id = params.serviceId;
      section.type = 'service';
    } else if(params.policyId) {
      section.title = 'Policy';
      section.id = params.policyId;
      section.type = 'policy';
    }

    return section;
  },
  getSubSections: function(section, params) {
    var sections;
    if (section === 'Domain') {
      sections = {
        role: {
          link: '/athenz/domain/' + params.domainId + '/role',
          name: 'Roles'
        },
        service: {
          link: '/athenz/domain/' + params.domainId + '/service',
          name: 'Services'
        },
        policy: {
          link: '/athenz/domain/' + params.domainId + '/policy',
          name: 'Policies'
        }
      };
    }

    var activeSubSection = sections ? sections[params.subSection || params.section] : null;
    if (activeSubSection) {
      activeSubSection.active = 'active';
    }

    return sections;
  },
  initCommonData: function(req, res) {
    res.locals.allParams = _.assign({}, req.params, req.query);
    res.locals.allParams.token = req.body ? req.body.token : '';
    res.locals.currentDomain = req.params.domainId;
    res.locals.section = res.locals.section || this.getCurrentSection(req.params);
    res.locals.entityType = res.locals.section.type;
    res.locals.subSections = this.getSubSections(res.locals.section.title, req.params);
    res.locals.appEnv = req.config.envLabel;

    res.locals.navApps = [{
      link: '/athenz',
      name: 'Athenz',
      active: 'active'
    }];

    res.locals.productionsvc = req.config.serviceFQN === 'athenz.console.uiproduction';

    this.setAppContextMessage(req, res);
  },
  /**
   * This adds content to appheader partial.
   */
  setAppContextMessage: function(req, res) {
    var entity = _.capitalize(res.locals.entityType);

    if(req.query.failed) {
      res.locals.appContextMessage = req.query.failed;
      res.locals.appContextMessageType = 'error';
    } else if (req.query.success) {
      res.locals.appContextMessage = req.query.success;
      res.locals.appContextMessageType = 'success';
    } else {
      Object.keys(req.query).forEach(function(param) {
        if(MESSAGES[param]) {
          res.locals.appContextMessage = _.template(MESSAGES[param])({entity: entity});
          res.locals.appContextMessageType = param.indexOf('Error') !== -1 ? 'error' : '';
        }
      });
    }
  },
  cleanupOriginalUrl: function(currentUrl) {
    var urlObj = url.parse(currentUrl, true);

    delete urlObj.search;
    cleanupFields.forEach(function(field) {
      delete urlObj.query[field];
    });

    return url.format(urlObj);
  },
  isUriSectionOf: function(uriSection, section) {
    return uriSection && uriSection.indexOf(section) !== -1;
  },
  getDomainTypes: function(params) {
    var domainTypes = {
      domain: {
        link: '/athenz/domain/create/domain',
        name: 'Top Level'
      },
      subdomain: {
        link: '/athenz/domain/create/subdomain',
        name: 'Sub domain'
      },
      userdomain: {
        link: '/athenz/domain/create/userdomain',
        name: 'Personal'
      }
    };

    var activeDomain = domainTypes[params.domainType] ? params.domainType : 'domain';
    domainTypes[activeDomain].active = 'active';

    return domainTypes;
  }
};
