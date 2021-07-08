'use strict';

const ZPEMatch = function (value) {
    const equalMatches = function (val) {
        return val === value;
    };

    const startswithMatches = function (val) {
        return val.startsWith(value.substring(0, value.length - 1));
    };

    const allMatches = function (val) {
        return true;
    };

    const regexMatches = function (val) {
        let replaced = '' + value;
        replaced = replaced.replace(/([.+^$[\]\\(){}|-])/g, '\\$1');
        replaced = replaced.replace(/\?/g, '.').replace(/\*/g, '.*');
        replaced = `^${replaced}$`;

        const regexp = new RegExp(replaced);

        if (val.match(regexp)) {
            return true;
        }
        return false;
    };

    return {
        equal: {
            name: 'equal',
            matches: equalMatches,
        },
        startswith: {
            name: 'startswith',
            matches: startswithMatches,
        },
        all: {
            name: 'all',
            matches: allMatches,
        },
        regex: {
            name: 'regex',
            matches: regexMatches,
        },
    };
};

module.exports = ZPEMatch;
