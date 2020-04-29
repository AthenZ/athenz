/*globals userId:false */
'use strict';

(function($) {
  var selectizeCommon = require('./selectize').selectizeCommon;

  var domainForm = $('.domain-form form');

  if(domainForm.length) {
    var userFeedback = $('#user-feedback');
    var allUserFeedback = $('.error-message');
    var submitButton = $('.domain-form form :submit');
    var auditCheckbox = $('#audit');
    var domainName = $('input[name="name"]', domainForm);

    selectizeCommon(domainForm);
  }
})(window.jQuery);
