const passport = require('passport-strategy');
const util = require('util');
const expressOkta = require('@vzmi/express-okta-oath');
const debug = require('debug')('AthenzUI:server:strategies:OktaStrategy');
/**
 * `Strategy` constructor.
 *
 * @param expressApp
 * @param config
 * @param secrets
 * @param timeout
 * @api public
 */
function Strategy(expressApp, config, secrets) {
    // initial set up with config
    passport.Strategy.call(this);
    this.name = 'ui-auth';
    this.okta = getOkta(config, secrets, undefined);

    expressApp.use(this.okta.callback());
    expressApp.use(this.okta.protect({}));
    debug('[Startup] done configuring AuthStrategy');
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

function oktaConfig(config, secrets, timeout) {
    return {
        action: 'redirect',
        callbackPath: config.oktaCallBackPath || '/oauth2/callback',
        clientID: config.oktaClientId || '0oa48m26py0XJWzcE1t7',
        clientSecret: secrets.oktaClient,
        allowCname: config.allowCname || false,
        allowedDomains: config.allowedDomains || [],
        serverURL: config.serverURL,
        cookieDomain: config.oktaCookieDomain,
        oktaEnv: config.oktaEnv || 'prod',
        timeout: timeout ? timeout : config.oktaTimeout,
        athenzService: config.athenzDomainService || 'sys.auth.ui',
        athenzPrivateKeyPath:
            config.athenzPrivateKeyPath ||
            '/var/lib/sia/keys/sys.auth.ui.key.pem',
        athenzX509CertPath:
            config.athenzX509CertPath ||
            '/var/lib/sia/certs/sys.auth.ui.cert.pem',
    };
}

function getOkta(config, secrets, timeout) {
    return new expressOkta.Okta(oktaConfig(config, secrets, timeout));
}

/**
 * Authenticate request after coming back from Okta Validator
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
    // gets called on every request
    if (!req.okta) {
        debug('Okta details not found, url: %o', req.originalUrl);
    } else if (req.okta.status !== 'VALID') {
        debug(
            'Invalid okta, url: %o error: %o',
            req.originalUrl,
            req.okta.error
        );
    }
    //session expiry
    if (!req.session.iat) {
        req.session.iat = req.okta.claims.iat;
    } else if (req.session.iat !== req.okta.claims.iat) {
        delete req.session.iat;
        debug('problem with session for URL: %s', req.originalUrl);
        this.redirect(req.originalUrl);
        return;
    }

    // user check
    if (!req.session.shortId) {
        if (!req.okta.claims.short_id) {
            req.session.shortId = req.okta.claims.sub;
        } else {
            req.session.shortId = req.okta.claims.short_id;
        }
    } else if (
        req.session.shortId !== req.okta.claims.short_id &&
        req.session.shortId !== req.okta.claims.sub
    ) {
        delete req.session.shortId;
        debug('problem with user for URL: %s', req.originalUrl);
        this.redirect(req.originalUrl);
        return;
    }
    this.success();
};

/**
 * Register a function used to configure the strategy.
 * not being used
 *
 * @api public
 * @param identifier
 * @param done
 */
Strategy.prototype.configure = function (identifier, done) {
    done();
};

module.exports = Strategy;
module.exports.okta = getOkta;
