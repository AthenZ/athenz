/*globals userId:false */
'use strict';

var $ = require('jquery');
var selectizeCommon = require('./selectize').selectizeCommon;
require('select2');

(function() {
  var domainForm = $('.domain-form form');

  if(domainForm.length) {
    var userFeedback = $('#user-feedback');
    var allUserFeedback = $('.error-message');
    var submitButton = $('.domain-form form :submit');
    var auditCheckbox = $('#audit');
    var domainName = $('input[name="name"]', domainForm);

    selectizeCommon(domainForm);
  }
})();
