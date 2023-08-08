'use strict';

const config = {
    local: {
        serverCipherSuites: null,
    },
};

module.exports = function () {
    let env = process.env.APP_ENV ? process.env.APP_ENV : 'local';
    const c = config[env];
    c.env = env;
    return c;
};
