'use strict';

(function($) {
  var common = require('./common');
  var domainSection = $('.manage-container .domain-list');
  if(domainSection.length) {
    common.handleButtonSubmit(
      domainSection,
      'button.delete-domain',
      common.handleEntityDelete({
        error: 'Failed to delete Domain.',
        success: 'Successfully deleted Domain.'
      }),
      'Domain'
    );

    domainSection.on(
      'click',
      '.icon-edit',
      common.handleRowEdit('domain', '.edit', function(editContainer, parentContainer) {
        var accountInput = $('input[name="accountid"]', parentContainer);
        accountInput.prop('disabled', false).focus().select();

        // One of the cases where editContainer is actually intermixed with
        // parentContainer, forcing to do few workarounds like these. In all
        // other uses of handleRowEdit there is a clear separation between two.
        editContainer.destroy = editContainer.destroy.bind(editContainer, function() {
          accountInput.prop('disabled', true).prop('value', accountInput.attr('value'));
        });

        common.handleFormSubmit($('form', parentContainer), function(data, err) {
          if(!err && data) {
            accountInput.attr('value', accountInput.prop('value'));
            editContainer.destroy();
          } else {
            $('button[type=submit]', editContainer).prop('disabled', false);
            var message = err.message || 'Failed to update Cloud Account ID. Please contact support';
            $('.error-message', editContainer).text(message);
          }
        });
      })
    );
  }
})(window.jQuery);
