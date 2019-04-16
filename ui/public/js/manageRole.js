'use strict';

(function($) {
  var common = require('./common');
  var roleHelper = require('./roleHelper');

  var roleSection = $('.roles-section');

  if(roleSection.length) {
    var deleteMemberError = function(result) {
      var currentRole = $('input[name=roles]', result.targetButton.closest('form'))
          .prop('value');
      var dataError = result.data && result.data[currentRole] && result.data[currentRole].error ? true : false;
      var message = 'Failed to delete member from role';
      if(dataError) {
        message += ': ' + result.data[currentRole].msg;
      }
      return {
        message: message,
        dataError: dataError
      };
    };

    var addMemberToRoles = function(result) {
      result.params.roles.filter(function(role) {
        return !result.roles[role].error;
      }).forEach(function(role) {
        var roleNode = $('#' + role + '-info');
        $('.role-members', roleNode)
            .append(common.getRoleMemberNode(result.params.member, result.params.domain));
      });
    };

    roleSection.on('click', 'button.add-members', function(e) {
      var addModal = $('.add-people-modal', roleSection);

      e.stopPropagation();
      common.resetForm(addModal);
      common.showModal.call(addModal);

      roleHelper.populateRoles('addmember', $('.roles', addModal));

      $('input[name="members"]', addModal).focus();
      addModal.on('click', 'input[type=checkbox]',
                  common.checkboxClickHandler.bind(addModal, $('.roles', addModal)));

      common.handleFormSubmit($('form', addModal), function(data) {
        var resultsModal = $('.results-modal', roleSection);

        addModal.destroy();

        common.showModal.call(resultsModal);
        roleHelper.populateRoles('results',  $('.roles', resultsModal));

        addMemberToRoles(data);

        $('.roles > div', resultsModal).each(function() {
          var role = $(this),
            roleName = $('span', role).text(),
            result = data.roles[roleName];

          if(result) {
            if(result.error) {
              role.addClass('role error');
              $('.icon', role).addClass('icon-exclamation').prop('title', result.msg);
            } else {
              role.addClass('role success');
              $('.icon', role).addClass('icon-checkmark').prop('title', result.msg);
            }
          }
        });
      });
    });

    roleSection.on('click', 'button.add-role', function(e) {
      e.stopPropagation();
      var roleModal = $('.add-role-modal', roleSection);
      common.resetForm(roleModal);
      common.showModal.call(roleModal);
      $('input[name=name]', roleModal).focus();
      roleModal.on('click', '.role-type input[name=category]', function(event) {
        if(event.target.value === 'delegated') {
          $('input[name=delegated-domain]', roleModal).prop('disabled', false);
          $('input[name=members]', roleModal).prop('disabled', true)
              .prop('placeholder', 'Not applicable for Delegated Role');
        } else {
          $('input[name=delegated-domain]', roleModal).prop('disabled', true);
          $('input[name=members]', roleModal).prop('disabled', false)
              .prop('placeholder', 'Enter Role members (csv)');
        }
      });

      common.handleFormSubmit($('form', roleModal), function(data, err) {
        if(!err && data) {
          roleModal.destroy();
          common.addRowToTable($('.roles-list', roleSection), data);
        } else {
          $('button[type=submit]', roleModal).prop('disabled', false);
          $('.error-message', roleModal).text('Failed to create Role. Please contact support');
        }
      });
    });

    common.handleButtonSubmit(
      roleSection,
      '.role-delete button',
      common.handleEntityDelete({
        error: 'Failed to delete role',
        success: 'Successfully deleted role'
      }),
      'Role'
    );

    common.handleButtonSubmit(
      roleSection,
      '.role-admin-delete button',
      common.handleEntityDelete({
        error: deleteMemberError,
        success: 'Successfully deleted member from role'
      }, 'li'),
      'Role Member'
    );

    common.handleRowExpandClick(roleSection, 'role');
  }
})(window.jQuery);
