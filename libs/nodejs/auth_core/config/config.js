'use strict';

var fs = require('fs');

module.exports = function() {
  var defaultConfig = require('./default-config.js')();
  var extendedConfig = {};
  if (__dirname !== process.cwd() + '/config') {
    try {
      fs.statSync(process.cwd() + '/config/config.js');
      extendedConfig = require(process.cwd() + '/config/config.js')();
    } catch (err) {
      if (err.code !== 'ENOENT') {
        console.error(err);
      }
    }
  }
  var c = (extendedConfig.auth_core || {});

  return Object.assign(defaultConfig, c);
};
