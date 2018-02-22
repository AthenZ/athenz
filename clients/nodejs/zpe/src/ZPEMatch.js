'use strict';

const ZPEMatch = function (value) {
  const equalMatches = function (val) {
    return val === value;
  };

  const startswithMatches = function (val) {
    return val.startsWith(value.substring(0, value.length - 1));
  };

  const endswitchMatches = function (val) {
    return val.endsWith(value.substring(1,value.length));
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
    endswith: {
      name: 'endswith',
      matches: endswitchMatches
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
