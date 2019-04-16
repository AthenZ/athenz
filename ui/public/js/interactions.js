'use strict';

(function($) {
  var common = require('./common');
  $('.show-details').click(function() {
    var container = $(this).closest('.expandable-content');
    if(container) {
      container.toggleClass('expanded');
    }
    if ($(this).text() === 'Show Details') {
      $(this).text('Hide Details');
    } else {
      $(this).text('Show Details');
    }
  });

  /**
   * Display info row next to the entity row.
   * Logic depends on the having the id of info row same as entity name which is
   * the entity row's first cell's text value.
   */
  $('body').on('click', '.icon-more', common.handleMoreClick);
})(window.jQuery);
