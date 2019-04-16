'use strict';

const $ = window.jQuery;

var getId = function(id) {
  return '#' + id.replace(/(:|\.|\[|\]|,)/g, '\\$1');
};

var handleMoreClick = function() {
  var parentTr = $(this).closest('tr');
  var infoId = parentTr.attr('id') + '-info';
  var infoNode = $(getId(infoId));

  if(infoNode.length && !infoNode.hasClass('editing')) {
    infoNode.toggleClass('hidden');
    var infoVisible = !infoNode.hasClass('hidden');
    parentTr.toggleClass('active', infoVisible);
    return infoVisible ? infoNode : null;
  }
};

module.exports = {
  submitPrimaryButtonOnEnter: function(e) {
    // We have forms with multiple submits, especially delete and submit.
    // Since browsers pick first submit button as enter key target, this results
    // in undesireable outcome. So hijacking enterkey press to submit primary
    var form = this;
    if(e.keyCode === 13) {
      var primaryButton = $('button.primary', form);
      if(primaryButton.length) {
        e.preventDefault();
        primaryButton.click();
      }
    }
  },
  disableForm: function() {
    // Disable *after*  submit
    var form = this;
    setTimeout(function() {
      $('button[type=submit]', form).prop('disabled', true);
    }, 0);
  },
  showModal: function(noForceClose) {
    var modal = this;
    modal.addClass('visible');
    modal.children('input').focus();
    var modalContainer = $('.app-container');

    modal.destroy = function() {
      modal.removeClass('visible').off();
      modalContainer.removeClass('modal-active').off();
    };

    modalContainer.addClass('modal-active');

    if(!noForceClose) {
      // Allows closing modal when clicking outside of modal
      modalContainer.on('click', function(e) {
        if (modalContainer.is(e.target)) {
          modal.destroy();
        }
      });
    }

    modal.on('click', '.close', function() {
      modal.destroy();
    });
  },
  resetForm: function(form, resetSelect) {
    $('input[type=text]', form).val('');
    $('textarea', form).val('');
    $('input[type=checkbox]', form).prop('checked', false);
    $('.error-message', form).text('');

    $('button', form).prop('disabled', false);

    if(resetSelect) {
      var selects = $('select', form);
      if(selects.length) {
        selects.select2('destroy');
      }
    }
  },
  checkboxClickHandler: function(checkboxContainer, e) {
    var modal = this;
    var checkBoxes = $('input', checkboxContainer),
      selectAll = $('.all input', modal);

    if(e.target.value === 'all') {
      checkBoxes.prop('checked', e.target.checked);
    }

    var currentChecked = $('input:checked', checkboxContainer);

    selectAll.prop('checked', currentChecked.length === checkBoxes.length);
    $('button.primary', modal).prop('disabled', !currentChecked.length);
  },
  handleFormSubmit: function(form, cb) {
    //FIXME: Handle cleanup of this event on modal destroy
    var _me = this;
    return form.on('submit', function(e) {
      e.preventDefault();
      e.stopPropagation();
      _me.disableForm.call(e.target);
      $.ajax({
        url: $(this).attr('action'),
        data: _me.getFormData(this),
        processData: false,
        contentType: false,
        type: 'POST'
      }).then(function(data) {
        return cb(data);
      }, function(xhr) {
        var message = xhr.responseText && !xhr.responseText.includes('html') ?
              xhr.responseText : '';
        return cb(null, message ? {message} : xhr);
      });
    });
  },
  showDeleteModal: function(message, cb) {
    var modal = $('.delete-modal');
    $('.message', modal).text(message);
    this.showModal.call(modal, true);
    modal.on('click', 'button', function() {
      if(this.value === 'delete') {
        cb();
      }
    });
  },
  /**
   * Currently used to handle all delete button actions which require a form
   * submit. So it's safe for askConfirmation to default to true. Will revisit
   * this later, if use of this helper function expands.
   */
  handleButtonSubmit: function(container, buttonSelector, cb, entity, noAskConfirmation) {
    var _this = this;
    return container.on('click', buttonSelector, function(e) {
      e.preventDefault();
      e.stopPropagation();

      var currentButton = this;
      var submitForm = function() {
        currentButton.setAttribute('disabled', true);

        $.ajax({
          url: currentButton.formAction,
          data: _this.getFormData(currentButton.closest('form')),
          processData: false,
          contentType: false,
          type: 'POST'
        }).done(function(data) {
          if(typeof data !== 'object') {
            return cb('Invalid API response');
          }
          cb(null, {targetButton: currentButton, data: data});
        }).error(function(status, data) {
          currentButton.removeAttribute('disabled');
          cb(data);
        });
      };

      if(!noAskConfirmation) {
        // TODO:: Add name to entity - Responsibility of caller to ensure that
        // entity has name in it.
        // FIXME:: This also assumes that it's a delete Modal
        var message = `Once the ${entity} is deleted it cannot be recovered`;
        _this.showDeleteModal(message, submitForm);
      } else {
        submitForm();
      }
    });
  },
  getRoleMemberNode: function(member, domain) {
    return '<li><div><span>' + member + '</span>' +
        '<input type="hidden" name="member" value="' + member + '" />' +
        '<button formaction="/athenz/domain/' + domain + '/member/delete "' +
        'type="submit" class="icon-trash"></button></div></li>';
  },
  addRowToTable: function(table, html) {
    var node = $(html);
    this.toggleTableRowClass(table);
    $('button[type=submit]', node).prop('disabled', false);
    table.prepend(node);
    return node;
  },
  showAppMessage: function(type, message) {
    var appMessage = $('.app-header .app-message');
    appMessage.removeClass('hidden success error').addClass(type).text(message);
  },
  toggleTableRowClass: function(table) {
    var oddRows = $('.odd', table);
    var evenRows = $('.even', table);
    oddRows.removeClass('odd').addClass('even');
    evenRows.removeClass('even').addClass('odd');
  },
  setToken: function(container) {
    if(this.token) {
      container = container || window.body;
      $('input[name=token]', container).val(this.token);
      $('button[type=submit]:disabled', container).removeAttr('disabled');
    }
  },
  processToken: function(token) {
    this.token = token;
    this.setToken();
  },
  getFormData: function(form) {
    if(!form) {
      form = document.createElement('form');
    }

    if(!form.children.namedItem('token')) {
      var tokenNode = document.createElement('input');
      tokenNode.type = 'hidden';
      tokenNode.name = 'token';
      tokenNode.value = this.token;
      form.appendChild(tokenNode);
    }

    return new FormData(form);
  },
  renderRowDetails: function(type, infoNode, cb) {
    var _this = this;
    var url, name;
    switch(type) {
      case 'role':
        name = $('input[name=roles]', infoNode).prop('value');
        url = `/athenz/ajax/domain/${window.athenzParams.domainId}/role/${name}/info`;
        break;
      case 'service':
        name = $('input[name=service]', infoNode).prop('value');
        url = `/athenz/ajax/domain/${window.athenzParams.domainId}/service/${name}/info`;
        break;
      case 'policy':
        name = $('input[name=policy]', infoNode).prop('value');
        url = `/athenz/ajax/domain/${window.athenzParams.domainId}/policy/${name}/info`;
        break;
      default:
        return cb(infoNode);
    }

    $.ajax({
      url: url
    }).then(function(html) {
      infoNode.html($(html).get(2).children);
      _this.setToken(infoNode);
      if(typeof cb === 'function') {
        cb(infoNode);
      }
    }, function() {
      $('.error-message', infoNode).text(`Failed to fetch ${type} details`);
    });
  },
  handleMoreClick: handleMoreClick,
  handleRowExpandClick: function(container, type) {
    var _this = this;
    container.on('click', '.icon-more', function(e) {
      e.stopPropagation();
      var infoNode = handleMoreClick.call(this);
      if(infoNode) {
        _this.renderRowDetails(type, infoNode);
      }
    });
  },
  handleEntityDelete: function(messages, parentSelector) {
    var _this = this;
    return function(err, data) {
      var dataError = false;
      var message = '';
      if(typeof messages.error === 'function') {
        var e = messages.error(data);
        dataError = e.dataError;
        message = e.message;
      } else {
        message = messages.error;
      }

      if(err || dataError) {
        _this.showAppMessage('error', message);
      } else {
        _this.showAppMessage('success', messages.success);
        var row = data.targetButton.closest(parentSelector || 'tr');
        var infoRow = $(getId(`${row.id}-info`));
        if(infoRow.length) {
          // Delete part of a main table row.
          infoRow.remove();
          $(row).nextAll(':not(.info)').toggleClass('even').toggleClass('odd');
        }
        row.remove();
      }
    };
  },
  handleRowEdit: function(type, editContainer, cb) {
    var _this = this;
    return function() {
      var infoNode = handleMoreClick.call(this) || handleMoreClick.call(this);
      if(infoNode && infoNode.length) {
        infoNode.addClass('editing');
        _this.renderRowDetails(type, infoNode, function() {
          var addContainer = $(editContainer, infoNode);
          addContainer.removeClass('hidden');

          addContainer.destroy = function(fn) {
            addContainer.addClass('hidden').off();
            infoNode.removeClass('editing');
            _this.resetForm(addContainer, true);
            if(typeof fn === 'function') {
              fn();
            }
          };

          addContainer.on('click', '.close', function() {
            addContainer.destroy();
          });

          cb(addContainer, infoNode);
        });
      }
    };
  }
};
