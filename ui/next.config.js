const appConfig = require('./src/config/config')();
const { buildClientEnv } = require('./src/config/expose-client-env');

module.exports = {
    env: buildClientEnv(appConfig),
};
