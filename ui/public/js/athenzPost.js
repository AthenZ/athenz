'use strict';

(function($) {
  var common = require('./common');

  var fetchAuthSvcToken = function() {
    /* global zms, serviceFQN */
    if (zms !== '' && serviceFQN !== '') {
      var cred = Buffer.from($('input[name=username]').val() + ':' + $('input[name=password]').val()).toString('base64');
      $.ajax({
        url: zms + 'user/_self_/token?services=' + serviceFQN,
        method: 'GET',
        crossDomain: true,
        headers: {
          'Authorization': 'Basic ' + cred
        },
        xhrFields: {
          withCredentials: true
        },
        retryLimit: 3,
        success: function(result) {
          common.processToken(result.token);
          $('form[name=login]').submit();
        },
        error: function(jqXHR, textStatus, errorThrown) {
          console.log('Unable to fetch auth service user token: ', jqXHR, textStatus, errorThrown);
        }
      });
    }
  };

  $('form[name=auth]').submit(function(e) {
    e.preventDefault();

    // If token form field is found on the page, then fetch the token
    if ($('input[name=token]').length || $('button[type=submit]').length) {
      fetchAuthSvcToken(zms, serviceFQN);
    }
  });
})(window.jQuery);
