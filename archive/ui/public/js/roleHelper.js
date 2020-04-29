'use strict';

const $ = window.jQuery;

module.exports = {
  populateRoles: function(context, rolesNode) {
    var roles = $('.roles-section table .name').map(function() {
      return $(this).text();
    }).get();
    var htmlData = roles.map(function(role) {
      var html;
      switch(context) {
        case 'addmember':
          html = `<label class="role">
          <input type="checkbox" name="roles" value="${role}" />
          <span class="icon-checkbox">${role}</span>
          </label>`;
          break;
        case 'results':
          html = `<div class="">
          <span class="name">${role}</span>
          <span class="icon"></span>
          </div>`;
          break;
      }
      return html;
    });

    rolesNode.html('');
    rolesNode.append(htmlData);
  }
};
