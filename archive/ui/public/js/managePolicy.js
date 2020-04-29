'use strict';

(function($) {
  var common = require('./common');

  var policySection = $('.policies-section');
  if(policySection.length) {
    var policyModal = $('.add-policy-modal', policySection);

    $('select[name="role"]', policyModal).select2({
      minimumResultsForSearch: Infinity,
      data: window.athenzParams.roles.map(function(role) {
        return {id: role, text: role};
      }),
      placeholder: 'Select Role'
    });

    common.handleRowExpandClick(policySection, 'policy');

    common.handleButtonSubmit(
      policySection,
      'button.delete-policy',
      common.handleEntityDelete({
        error: 'Failed to delete Policy.',
        success: 'Successfully deleted Policy.'
      }),
      'Policy'
    );

    common.handleButtonSubmit(
      policySection,
      'button.delete-statement',
      common.handleEntityDelete({
        error: 'Failed to delete Policy Rule.',
        success: 'Successfully deleted Policy Rule.'
      }),
      'Policy Rule'
    );

    policySection.on(
      'click',
      '.icon-trust',
      common.handleRowEdit('policy', '.add', function(addContainer, parentContainer) {
        $('select[name="role"]', addContainer).select2({
          minimumResultsForSearch: Infinity,
          data: window.athenzParams.roles.map(function(role) {
            return {id: role, text: role};
          }),
          placeholder: 'Select Role'
        });
        $('input[name="action"]', addContainer).focus();

        common.handleFormSubmit($('form', addContainer), function(data, err) {
          if(!err && data) {
            addContainer.destroy();
            common.addRowToTable($('.rules table tbody', parentContainer), data)
                .addClass('active-dark');
          } else {
            $('button[type=submit]', addContainer).prop('disabled', false);
            var message = err.message || 'Failed to add Rule. Please contact support';
            $('.error-message', addContainer).text(message);
          }
        });
      })
    );

    policySection.on('click', 'button.add-policy', function(e) {
      e.stopPropagation();
      common.resetForm(policyModal);
      common.showModal.call(policyModal);
      $('input[name=name]', policyModal).focus();

      common.handleFormSubmit($('form', policyModal), function(data, err) {
        if(!err && data) {
          policyModal.destroy();
          common.addRowToTable($('.list', policySection), data);
        } else {
          $('button[type=submit]', policyModal).prop('disabled', false);
          var message = err.message || 'Failed to create Policy. Please contact support';
          $('.error-message', policyModal).text(message);
        }
      });
    });
  }
})(window.jQuery);
