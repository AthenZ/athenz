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
var dateUtils = require('./date');
var numberUtils = require('./number');

var selectTemplate = _.template(
  '<select name="<%=name%>" id="<%=name%>"' +
  '<%if (required) { print(" required") }%>>' +
  '<%if (insertBlank) { print("<option></option>") }%>' +
  '<%options.forEach(function(option) {%>' +
  '<option value="<%=option.key%>"><%-option.value%></option>' +
  '<% }); %></select>'
);

var inputTemplate = _.template(
  '<%options.forEach(function(option) {%>' +
  '<label><input id="<%=name%>" name="<%=name%>" type="<%=type%>" value="<%=option.key%>"' +
  '<%if (option.default) {print("checked=checked") }%>' +
  '<%if (option.interaction) {print(option.interaction) }%>/>' +
  '<span class="icon-<%=type%>"><%-option.value%></span></label>' +
  '<% });%>'
);

module.exports = {
  json: function(data) {
    return data ? JSON.stringify(data) : '""';
  },
  addToUriPath: function(currentUrl, appendPath) {
    var urlObj = url.parse(currentUrl);
    urlObj.pathname += '/' + appendPath;
    return url.format(urlObj);
  },
  addToUriQuery: function(currentUrl, param, value) {
    var urlObj = url.parse(currentUrl, true);
    urlObj.query[param] = value;
    delete urlObj.search;
    return url.format(urlObj);
  },
  renderSelect: function(name, options, insertBlank, required) {
    options = options || [];
    var args = {
      name: name,
      options: options,
      insertBlank: insertBlank,
      required: (required === 'required') ? true : false
    };
    return selectTemplate(args);
  },
  renderCheckBoxes: function(name, options) {
    return inputTemplate({options: options, name: name, type: 'checkbox'});
  },
  renderRadioButtons: function(name, options) {
    return inputTemplate({options: options, name: name, type: 'radio'});
  },
  renderStatusColumn: function(items) {
    var hasStatusText = _.find(items, function(item) {
      return item.statusText;
    });

    if(hasStatusText) {
      return '<th>Status</th>';
    }
    return '<th></th>';
  },
  /**
   * Kind of reverse. Follow array index numbers
   */
  getRowClass: function(index) {
    return (+index % 2 === 0) ? 'odd' : 'even';
  },
  formatDate: function(date) {
    return date ? dateUtils.formatDate(new Date(date)) : '';
  },
  ifFirstRow: function(index, options) {
    return index === 0 ? options.fn(this) : options.inverse(this);
  },
  ifShowDeleteDomainIcon: function(admin, domainType, options) {
    if(admin && domainType === 'Sub domain') {
      return options.fn(this);
    }
    return options.inverse(this);
  },
  getHome: (page) => {
    return '/athenz';
  },
  formatNumber: function(number, defaultValue) {
    defaultValue = defaultValue && typeof defaultValue === 'string' ? defaultValue : '';
    return numberUtils.formatNumber(number, defaultValue);
  },
  lowerCase: function(str) {
    return typeof str === 'string' ? str.toLowerCase() : '';
  }
};
