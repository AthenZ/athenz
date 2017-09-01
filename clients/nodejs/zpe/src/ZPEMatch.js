'use strict';

const ZPEMatch = function (value) {
  const equalMatches = function (val) {
    return val === value;
  };

  const startswithMatches = function (val) {
    return val.startsWith(value.substring(0, value.length - 1));
  };

  const allMatches = function (val) { return true; };

  const regexMatches = function (val) {
    if (val.match(value)) {
      return true;
    }
    return false;
  };
  return {
    equal: {
      name: 'equal',
      matches: equalMatches
    },
    startswith: {
      name: 'startswith',
      matches: startswithMatches
    },
    all: {
      name: 'all',
      matches: allMatches
    },
    regex: {
      name: 'regex',
      matches: regexMatches
    }
  };
};

module.exports = ZPEMatch;
