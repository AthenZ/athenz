'use strict';

var fs = require('fs');

module.exports = function() {
  var defaultConfig = require('./default-config.js')();
  try {
    fs.statSync(process.cwd() + '/config/extended-config.js');
    var extendedConfig = require(process.cwd() + '/config/extended-config.js')();
  } catch (err) {
    if (err.code !== 'ENOENT') {
      console.log(err);
    }
    var extendedConfig = {};
  }

  var c = Object.assign(defaultConfig, extendedConfig.auth_core);

  return c;
};
