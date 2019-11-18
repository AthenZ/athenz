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
 * Contains common data fetch functions which can be called fom multiple route handlers
 */

'use strict';

var addToUriQuery = require('./handlebarHelpers').addToUriQuery;
var config = require('../../config/config.js')();

function getErrorMessage(err) {
  if (err && err.message) {
    return (err.message.message) ? err.message.message : err.message;
  }
  if(typeof err === 'string') {
    return err;
  }
}

module.exports = {
  populateErrorData: function(viewData, req) {
    if (req.query.failed) {
      viewData.message = 'Error - ';
      viewData.message += (req.query.failed === 'yes') ?
          'Failed to create ' + viewData.type :
          req.query.failed;
    }
  },
  populateAppContextErrorMessage: function(holder, err) {
    var message = getErrorMessage(err);
    if(message) {
      holder.appContextMessageType = 'error';
      holder.appContextMessage = message;
    }
  },
  checkErr: function(errMsg, err) {
    return errMsg === getErrorMessage(err);
  },
  populateErrorMessage: function(toUrl, err) {
    console.log('err: ' + JSON.stringify(err));
    //TODO: make admin a link
    var message = 'Operation failed. Please contact application admin if this issue persists.';
    message = getErrorMessage(err) || message;
    return addToUriQuery(toUrl, 'failed', message);
  },
  ascertainDomainType: function(domain) {
    var domainData = {};
    if (domain) {
      var splits = domain.split('.');

      if (splits.length === 2 && domain.indexOf(config.userDomain + '.') === 0) {
        domainData.domainType = 'userdomain';
        domainData.name = splits[1];
      } else if (splits.length >= 2) {
        domainData.domainType = 'subdomain';
        domainData.parent = splits.slice(0, splits.length - 1).join('.');
        domainData.name = splits[splits.length - 1];
      } else {
        domainData.domainType = 'domain';
        domainData.name = domain;
      }
    }

    return domainData;
  },
  getDomainDisplayLabel: function(domain) {
    switch(domain) {
      case 'userdomain':
        return 'Personal';
      case 'subdomain':
        return 'Sub domain';
      case 'domain':
        return 'Top level';
      default:
        return 'None';
    }
  },
  getAdminLinks: function(admins) {
    if(admins && admins.length) {
      return admins.split(',').map(function(admin) {
        return admin;
      }).join(', ');
    }

    return [];
  },
  getErrorMessage: getErrorMessage,
  ajaxJsonHandler: function(res) {
    return function(err) {
      if(err) {
        //TODO: Send error message back to client and handle
        return res.status(500).json({});
      }
      return res.status(200).json({});
    };
  },
  ajaxHtmlHandler: function(res, cb) {
    return function(err, data) {
      if(err) {
        return res.status(500).send(getErrorMessage(err));
      }

      if(typeof cb === 'function') {
        return cb(data);
      }

      return res.status(200).send('Success');
    };
  },
  trimKey: function(key) {
    key = key.replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '')
      .replace(/ /g, '\n');

    return '-----BEGIN PUBLIC KEY-----' + key + '-----END PUBLIC KEY-----';
  },
  y64Encode: function(key) {
    return Buffer.from(key)
      .toString('base64')
      .replace(/\+/g, '.')
      .replace(/\//g, '_')
      .replace(/=/g, '-');
  },
  y64Decode: function(key) {
    var b64 = key.replace(/\./g, '+')
      .replace(/_/g, '/')
      .replace(/-/g, '=');

    return Buffer.from(b64, 'base64').toString();
  }
};
