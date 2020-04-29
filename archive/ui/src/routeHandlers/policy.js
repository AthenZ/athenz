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
var conf = require('../utils/conf');

var getResourceName = function(resource, domainId) {
  return resource.includes(':') ? resource : `${domainId}:${resource}`;
};

module.exports = {
  getPolicyRow: function(req, res) {
    pageUtils.initCommonData(req, res);
    var params = {
      domainName: req.params.domainId,
      policyName: req.params.policy,
      expand: true,
      auditLog: true
    };

    req.restClient.getPolicy(params, reqUtils.ajaxHtmlHandler(res, function(policy) {
      policy.active = 'active';
      policy.domainId = req.params.domainId;
      viewUtils.populatePolicyData(policy);
      policy.assertions.forEach(assertion => {
        assertion.deleteUrl = `/athenz/domain/${policy.domainId}/policy/${policy.name}/assertion/${assertion.id}/delete`;
      });

      res.render('policyrow', {
        layout: false,
        policyTypes: conf.POLICY_TYPES,
        policies: [policy]
      });
    }));
  },
  addPolicy: function(req, res) {
    pageUtils.initCommonData(req, res);
    var params = {
      domainName: req.params.domainId,
      policyName: req.body.name,
      policy: {
        name: req.params.domainId + ':policy.' + req.body.name,
        assertions: [{
          role: `${req.params.domainId}:role.${req.body.role}`,
          resource: getResourceName(req.body.resource, req.params.domainId),
          effect: req.body.effect,
          action: req.body.action
        }]
      }
    };

    req.restClient.putPolicy(params, reqUtils.ajaxHtmlHandler(res, function() {
      var policy = params.policy;
      policy.active = 'active';
      policy.modified = new Date();
      policy.domainId = req.params.domainId;
      viewUtils.populatePolicyData(policy);

      res.render('policyrow', {
        layout: false,
        policyTypes: conf.POLICY_TYPES,
        policies: [policy]
      });
    }));
  },
  deletePolicy: function(req, res) {
    var params = {
      domainName: req.params.domainId,
      policyName: req.params.policy
    };
    req.restClient.deletePolicy(params,  reqUtils.ajaxJsonHandler(res));
  },
  deleteAssertion: function(req, res) {
    var params = {
      domainName: req.params.domainId,
      policyName: req.params.policy,
      assertionId: req.params.id
    };
    req.restClient.deleteAssertion(params, reqUtils.ajaxJsonHandler(res));
  },
  addAssertion: function(req, res) {
    var params = {
      domainName: req.params.domainId,
      policyName: req.params.policy,
      assertion: {
        role: `${req.params.domainId}:role.${req.body.role}`,
        resource: getResourceName(req.body.resource, req.params.domainId),
        effect: req.body.effect,
        action: req.body.action
      }

    };
    req.restClient.putAssertion(params, reqUtils.ajaxHtmlHandler(res, function(data) {
      params.assertion.layout = false;
      params.assertion.id = data.id;
      params.assertion.deleteUrl =
          `/athenz/domain/${params.domainName}/policy/${params.policyName}/assertion/${data.id}/delete`;
      res.render('partials/assertionrow', params.assertion);
    }));
  }
};
