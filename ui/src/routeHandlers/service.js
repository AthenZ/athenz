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
  getServiceRow: function(req, res) {
    pageUtils.initCommonData(req, res);
    var params = {
      domain: req.params.domainId,
      service: req.params.service,
      expand: true,
      auditLog: true
    };

    req.restClient.getServiceIdentity(params, reqUtils.ajaxHtmlHandler(res, function(service) {
      service.active = 'active';
      service.domainId = req.params.domainId;
      service.publicKeys.forEach(key => {
        key.key = reqUtils.y64Decode(key.key);
        key.deleteUrl = `/athenz/domain/${service.domainId}/service/${req.params.service}/key/${key.id}/delete`;
      });
      viewUtils.populateServiceData(service);
      res.render('partials/servicerow', Object.assign({allParams: res.locals.allParams, layout: false}, service));
    }));
  },
  addService: function(req, res) {
    pageUtils.initCommonData(req, res);
    var params = {
      domain: req.params.domainId,
      service: req.body.name,
      detail: {
        name: req.params.domainId + '.' + req.body.name,
        publicKeys: [{
          id: req.body.keyId,
          key: reqUtils.y64Encode(reqUtils.trimKey(req.body.key))
        }],
        providerEndpoint: req.body.providerEndpoint,
        hosts: req.body.hosts ? req.body.hosts.split(',') : undefined,
        user: req.body.user,
        group: req.body.group
      }
    };
    req.restClient.putServiceIdentity(params, reqUtils.ajaxHtmlHandler(res, function() {
      var service = params.detail;
      service.active = 'active';
      service.domainId = req.params.domainId;
      service.modified = new Date();
      viewUtils.populateServiceData(service);
      service.publicKeys.forEach(key => {
        key.deleteUrl = `/athenz/domain/${service.domainId}/service/${service.name}/key/${key.id}/delete`;
      });

      res.render('partials/servicerow', Object.assign({allParams: res.locals.allParams, layout: false}, service));
    }));
  },
  deleteService: function(req, res) {
    var params = {
      domain: req.params.domainId,
      service: req.params.service
    };
    req.restClient.deleteServiceIdentity(params,  reqUtils.ajaxJsonHandler(res));
  },
  deleteKey: function(req, res) {
    var params = {
      domain: req.params.domainId,
      service: req.params.service,
      id: req.params.id
    };
    req.restClient.deletePublicKeyEntry(params, reqUtils.ajaxJsonHandler(res));
  },
  addKey: function(req, res) {
    var params = {
      domain: req.params.domainId,
      service: req.params.service,
      id: req.body.keyId,
      publicKeyEntry: {
        id: req.body.keyId,
        key: reqUtils.y64Encode(reqUtils.trimKey(req.body.key))
      }
    };
    req.restClient.putPublicKeyEntry(params, reqUtils.ajaxHtmlHandler(res, function() {
      params.publicKeyEntry.layout = false;
      params.publicKeyEntry.deleteUrl = `/athenz/domain/${params.domain}/service/${params.service}/key/${params.id}/delete`;
      params.publicKeyEntry.key = reqUtils.y64Decode(params.publicKeyEntry.key);
      res.render('partials/servicekeyrow', params.publicKeyEntry);
    }));
  }
};
