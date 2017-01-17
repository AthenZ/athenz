'use strict';

module.exports = {
  formatResults: function(data) {
    return {
      results: data.map(function(item) {
        if(typeof item === 'string') {
          return {text: item, id: item};
        }
        item.text = item.name;
        item.id = item.entityId;
        return item;
      })
    };
  },
  selectizeCommon: function() {}
};
