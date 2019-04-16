'use strict';

(function($) {
  var common = require('./common');

  var serviceSection = $('.services-section');
  if(serviceSection.length) {
    var serviceModal = $('.add-service-modal', serviceSection);
    common.handleRowExpandClick(serviceSection, 'service');

    common.handleButtonSubmit(
      serviceSection,
      'button.delete-service',
      common.handleEntityDelete({
        error: 'Failed to delete Service.',
        success: 'Successfully deleted Service.'
      }),
      'Service'
    );

    common.handleButtonSubmit(
      serviceSection,
      'button.delete-key',
      common.handleEntityDelete({
        error: 'Failed to delete Service key.',
        success: 'Successfully deleted key from Service.'
      }),
      'Service Key'
    );

    serviceSection.on(
      'click',
      '.icon-key',
      common.handleRowEdit('service', '.add', function(addContainer, parentContainer) {
        $('input[name="keyId"]', addContainer).focus();

        common.handleFormSubmit($('form', addContainer), function(data, err) {
          if(!err && data) {
            addContainer.destroy();
            common.addRowToTable($('.service-keys table tbody', parentContainer), data)
                .addClass('active-dark');
          } else {
            $('button[type=submit]', addContainer).prop('disabled', false);
            var message = err.message || 'Failed to add Key. Please contact support';
            $('.error-message', addContainer).text(message);
          }
        });
      })
    );

    serviceSection.on('click', 'button.add-service', function(e) {
      e.stopPropagation();
      common.resetForm(serviceModal);
      common.showModal.call(serviceModal);
      $('input[name=name]', serviceModal).focus();

      common.handleFormSubmit($('form', serviceModal), function(data, err) {
        if(!err && data) {
          serviceModal.destroy();
          common.addRowToTable($('.list', serviceSection), data);
        } else {
          $('button[type=submit]', serviceModal).prop('disabled', false);
          var message = err.message || 'Failed to create Service. Please contact support';
          $('.error-message', serviceModal).text(message);
        }
      });
    });
  }
})(window.jQuery);
