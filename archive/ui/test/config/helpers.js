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

var restClient = require('../../src/rdl-rest.js')({
  apiHost: 'host',
  rdl: require('../../config/zms.json')
})({});

var req = {
  config: {},
  params: {},
  restClient: restClient,
  query: {},
  header: function() {},
  error: function() {},
  originalUrl: 'url',
  user: {}
};

var res = {
  locals: {subSections: {roles: {}, resources: {}}, allParams: {}},
  status: function() {},
  send: function() {},
  json: function() {},
  render: function() {},
  redirect: function() {},
  set: function() {}
};

module.exports = {
  req: Object.assign({}, req),
  res: Object.assign({}, res),
  restClient: restClient
};
