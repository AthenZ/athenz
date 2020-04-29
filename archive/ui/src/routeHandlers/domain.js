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

var _ = require('lodash');
var NodeRestClient = require('node-rest-client').Client;

var statuses = require('../utils/conf').STATUSES;
var conf = require('../utils/conf');
var addToUriQuery = require('../utils/handlebarHelpers').addToUriQuery;
var pageUtils = require('../utils/page');
var reqUtils = require('../utils/req');
var viewUtils = require('../utils/view');
var conf = require('../utils/conf');

var domainHandler = require('../api/domain');
var rolesHandler = require('../api/roles');
var servicesHandler = require('../api/services');
var policiesHandler = require('../api/policies');

var config = require('../../config/config.js')();

var isEmpty = function(result) {
  if(Array.isArray(result) && result.length) {
    return false;
  }

  return !(result && Array.isArray(result.names) && result.names.length);
};

var responseHandler = function(req, res, cb) {
  return function(err, result) {
    if (err || isEmpty(result)) {
      reqUtils.populateAppContextErrorMessage(res.locals, err);
      return cb();
    }
    cb(Array.isArray(result) ? result : result.names);
  };
};

function handleAddDomainError(req, res, domainData, toUrl, err) {
  var msg = reqUtils.getErrorMessage(err);
  switch (msg) {
    case 'Entry already exists':
      var domainName = (domainData.parent ? domainData.parent + '.' : '') + domainData.name;
      toUrl = '/athenz/domain/' + domainName + '/role';
      toUrl = addToUriQuery(toUrl, 'failed', _.template(statuses.DOMAIN_ALREADY_EXISTS)({
        domainType: reqUtils.getDomainDisplayLabel(req.params.domainType),
        domain: domainName
      }));
      return res.redirect(303, toUrl);
    case 'Forbidden':
      switch(req.params.domainType) {
        case 'subdomain':
          rolesHandler.fetchRole({
            domainId: domainData.parent,
            roleId: 'admin'
          },
          req.restClient,
          function(roleErr, members) {
            toUrl = addToUriQuery(toUrl, 'admins', members ? members.join(',') : '');
            return res.redirect(303, toUrl);
          });
          break;
        case 'domain':
          if (err.admins) {
            toUrl = addToUriQuery(toUrl, 'admins', err.admins ? err.admins.join(',') : '');
          } else {
            toUrl = addToUriQuery(toUrl, 'failed', statuses.CREDENTIAL_ERROR);
          }
          return res.redirect(303, toUrl);
      }
      break;
    default:
      toUrl = reqUtils.populateErrorMessage(toUrl, err);
      return res.redirect(303, toUrl);
  }
}

module.exports = {
  addDomainsPage: function(req, res) {
    var viewData = {
      pageTitle: 'Add Domains',
      msg: [],
      section: {id: 'Create new Domain'},
      createDomainActive: 'active',
      audit: conf.AUDIT,
      toUrl: res.locals.originalUrl
    };
    viewData.admins = reqUtils.getAdminLinks(req.query.admins);
    viewData.domainTypes = pageUtils.getDomainTypes(req.params);

    pageUtils.setAppContextMessage(req, res);

    switch (req.params.domainType) {
      case 'domain':
        var nodeRestClient = new NodeRestClient();
        res.render('adddomains', viewData);
        break;
      case 'subdomain':
        res.render('adddomains', viewData);
        break;
      case 'userdomain':
        var userDomainId = config.userDomain + '.' + req.username;
        domainHandler.fetchDomainMetadata({
          domainId: userDomainId
        },
        req.restClient,
        function(err, result) {
          if (err) {
            // We don't want to populate user visible error variables here as its not relevant
            viewData.userId = userDomainId;
            res.render('adddomains', viewData);
          } else if(!err && result && result.name) {
            var toUrl = '/athenz/domain/' + result.name + '/role';
            toUrl = addToUriQuery(toUrl, 'success', _.template(statuses.DOMAIN_ALREADY_EXISTS)({
              domainType: reqUtils.getDomainDisplayLabel(req.params.domainType),
              domain: userDomainId
            }));
            toUrl = addToUriQuery(toUrl, 'domainName', result.name);
            res.redirect(303, toUrl);
          }
        });
        break;
      default:
        reqUtils.populateAppContextErrorMessage(viewData, {
          message: 'Domain not provided or Invalid domain type'
        });
        res.render('adddomains', viewData);
    }
  },
  addDomain: function(req, res) {
    var domainData = {
      adminUsers: [config.userDomain + '.' + req.username],
      name: req.body.name,
      parent: req.body.parent
    };

    var toUrl = res.locals.originalUrl;

    var cb = function(err, result) {
      if (err) {
        handleAddDomainError(req, res, domainData, toUrl, err);
      } else if (!err && result.name) {
        toUrl = '/athenz/domain/' + result.name + '/role';
        toUrl = addToUriQuery(toUrl, 'success', _.template(statuses.DOMAIN_SUCCESSFULLY_CREATED)({
          domainType: reqUtils.getDomainDisplayLabel(req.params.domainType),
          domain: result.name
        }));
        return res.redirect(303, toUrl);
      }
    };

    switch (req.params.domainType) {
      case 'domain':
        domainHandler.addDomain(domainData, req.restClient, cb);
        break;
      case 'subdomain':
        domainHandler.addSubDomain(domainData, req.restClient, cb);
        break;
      case 'userdomain':
        domainData.name = req.username;
        domainHandler.addUserDomain(domainData, req.restClient, cb);
        break;
      default:
        return cb({
          message: 'Domain not provided or Invalid domain type'
        });
    }
  },
  deleteDomain: function(req, res) {
    var domainData = reqUtils.ascertainDomainType(req.params.domainId);

    switch (domainData.domainType) {
      case 'domain':
        domainHandler.deleteDomain(domainData,
          req.restClient, reqUtils.ajaxJsonHandler(res)
        );
        break;
      case 'subdomain':
        domainHandler.deleteSubDomain(domainData,
          req.restClient, reqUtils.ajaxJsonHandler(res)
        );
        break;
      case 'userdomain':
        domainHandler.deleteUserDomain(domainData,
          req.restClient, reqUtils.ajaxJsonHandler(res)
        );
        break;
      default:
        return reqUtils.ajaxJsonHandler(res)({
          message: 'Domain not provided or Invalid domain type'
        });
    }
  },
  allDomains: function(req, res) {
    domainHandler.fetchAllDomains(req.query, req.restClient, reqUtils.ajaxHtmlHandler(res, function(data) {
      res.set('Cache-Control', 'private, max-age=3600');
      return res.json(data || []);
    }));
  },
  domainDetails: function(req, res, cb) {
    domainHandler.fetchDomainMetadata({
      domainId: res.locals.currentDomain
    },
    req.restClient,
    function(err, result) {
      res.locals.domainDetails = {};
      if (err) {
        reqUtils.populateAppContextErrorMessage(res.locals, err);
      } else {
        _.assign(res.locals.domainDetails, result);
      }
      cb();
    });
  },
  postMember: function(req, res) {
    var params = {
      domain: req.params.domainId,
      roles: typeof req.body.roles === 'string' ? [req.body.roles] : req.body.roles,
      member: req.body.members
    };
    rolesHandler.addMember(params, req.restClient, function(err, roles) {
      var response = {params: params, roles: roles || {}};
      if(err) {
        res.status(500);
        req.error(err);
      }
      return res.json(response);
    });
  },
  deleteMember: function(req, res) {
    var params = {
      domain: req.params.domainId,
      roles: typeof req.body.roles === 'string' ? [req.body.roles] : req.body.roles,
      member: req.body.member || req.params.member
    };

    rolesHandler.deleteMember(params, req.restClient, function(err, roles) {
      if(err) {
        res.status(500);
        req.error(err);
      }
      return res.json(roles || []);
    });
  },
  roleRoute: function(req, res) {
    var viewData = {
        pageTitle: 'Home : Roles',
        itemURI: '/athenz/domain/' + res.locals.currentDomain + '/role/',
        addRole: '/athenz/domain/' + res.locals.currentDomain + '/role/add',
        addMember: '/athenz/domain/' + res.locals.currentDomain + '/member/add',
        deleteMember: '/athenz/domain/' + res.locals.currentDomain + '/member/delete',
        roles: [],
        roleCategories: conf.ROLE_CATEGORIES
      },
      render = res.render.bind(res, 'domain', viewData),
      apiCb;

    apiCb = responseHandler(req, res, function(roles) {
      if(!roles) {
        return render();
      }
      roles =  viewUtils.moveRole(roles, res.locals.currentDomain + ':role.admin');
      viewData.roles = roles;
      roles.forEach(role => {
        role.domainId = req.params.domainId;
        role.members = [];
        viewUtils.populateRoleData(role);
      });
      render();
    });

    rolesHandler.fetchRoles(
      {domainId: res.locals.currentDomain},
      req.restClient,
      apiCb
    );
  },
  serviceRoute: function(req, res) {
    var viewData = {
        pageTitle: 'Home : Services',
        itemURI: '/athenz/domain/' + res.locals.currentDomain + '/service/',
        addService: '/athenz/domain/' + res.locals.currentDomain + '/service/add'
      },
      render = res.render.bind(res, 'domain', viewData),
      apiCb;

    apiCb = responseHandler(req, res, function(services) {
      if(!services) {
        return render();
      }

      viewData.services = services.map(service => {
        service.domainId = req.params.domainId;
        viewUtils.populateServiceData(service);
        return service;
      });
      render();
    });

    servicesHandler.fetchServices(
      {domainId: res.locals.currentDomain},
      req.restClient,
      apiCb
    );
  },
  policyRoute: function(req, res) {
    var viewData = {
        pageTitle: 'Home : Policies',
        itemURI: '/athenz/domain/' + res.locals.currentDomain + '/policy/',
        addPolicy: '/athenz/domain/' + res.locals.currentDomain + '/policy/add',
        policyTypes: conf.POLICY_TYPES
      },
      apiCount = 2,
      render = res.render.bind(res, 'domain', viewData),
      apiCb;

    apiCb = responseHandler(req, res, function(policies) {
      if(!policies) {
        return viewUtils.callCb(render, viewData, --apiCount);
      }

      viewData.policies = policies.map(policy => {
        policy.domainId = req.params.domainId;
        viewUtils.populatePolicyData(policy);
        return policy;
      });
      viewUtils.callCb(render, viewData, --apiCount);
    });

    policiesHandler.fetchPolicies(
      {domainId: res.locals.currentDomain},
      req.restClient,
      apiCb
    );

    rolesHandler.fetchRoles(
      {domainId: res.locals.currentDomain},
      req.restClient,
      function(err, roles) {
        if(!err && roles) {
          viewData.roles = roles.map(role => {
            viewUtils.populateRoleData(role);
            return role.name;
          }).sort();
          res.locals.allParams.roles = viewData.roles;
        }
        viewUtils.callCb(render, viewData, --apiCount);
      }
    );
  },
  editDomain: function(req, res) {
    var params = {
      domain: req.params.domainId
    };
    req.restClient.getDomain(params, function(err, data) {
      if(data) {
        params.name = params.domain;
        params.detail = data;

        delete data.id;
        delete data.modified;
        delete data.name;
        data.account = req.body.accountid;
        return req.restClient.putDomain(params, reqUtils.ajaxHtmlHandler(res));
      }
      res.status(500).send('Failed to fetch Domain data');
    });
  },
  handleAddDomainError: handleAddDomainError
};
