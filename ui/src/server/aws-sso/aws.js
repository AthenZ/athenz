'use strict';

const LIBS = {
        fs: require('fs'),
        sso: require('./aws-sso'),
    },
    ADMINSSO = new LIBS.sso.SSO('admin'),
    DEVSSO = new LIBS.sso.SSO('dev'),
    HOUR = 60 * 60; // 1 hour (in seconds)

const debug = require('debug')('AthenzUI:server:aws-sso:aws');

function awsLogin(req, res) {
    const params = {
        action: 'assume_aws_role',
        principal: 'user.' + req.session.shortId,
    };
    var times = { now: new Date() };
    const admin = req.url.toLowerCase().indexOf('admin') > -1;
    var sso = admin ? ADMINSSO : DEVSSO;
    if (admin) {
        times.expires = new Date(times.now.getTime() + 1000 * HOUR); // admin session is only valid for an hour
    } else {
        times.expires = new Date(times.now.getTime() + 1000 * 8 * HOUR);
    }
    var roleARNs = [];
    req.clients.zms.getResourceAccessList(params, function (err, list) {
        if (!list || !list.resources) {
            debug('[AWS-SSO] Error in AWS Login: %o', req.params);
            res.type('html').send(`
        <html>
          <h3>Error: There are no AWS roles associated with your account.</h3>
          <p>Check to make sure that your <tt>aws.*</tt> roles contain your user.<br/>
             E.g., if your account is 'jdoe', then <tt>aws.fed.admin.user</tt> should
             have <tt>user.jdoe</tt> as a member.</p>
          <p>If that does not work, please ask your Athenz domain admin for assistance.</p>
        </html>
      `);
            return;
        }
        list.resources.forEach(function (resources) {
            resources.assertions.forEach(function (assertion) {
                if (assertion.resource.toLowerCase().indexOf('admin') > -1) {
                    if (admin) {
                        roleARNs.push(assertion.resource);
                    }
                } else if (!admin) {
                    roleARNs.push(assertion.resource);
                }
            });
        });
        var accountNumber =
            req.params && req.params.accountNumber
                ? req.params.accountNumber
                : undefined;
        if (accountNumber) {
            accountNumber =
                typeof accountNumber === 'number'
                    ? accountNumber.toString()
                    : accountNumber;
            roleARNs = roleARNs.filter((an) => an.indexOf(accountNumber) > -1);
        }
        var roleName =
            req.params && req.params.roleName ? req.params.roleName : undefined;
        if (roleName) {
            roleName =
                typeof roleName == 'number' ? roleName.toString() : roleName;
            roleARNs = roleARNs.filter((rn) => rn.indexOf(roleName) > -1);
        }
        if (roleARNs.length === 0) {
            res.type('html').send(`
        <html>
          <h3>Error: There are no AWS roles associated with your account. Please ask your Athenz domain admin for assistance.</h3>
        </html>
      `);
        } else {
            var assertion = sso.makeAssertion(
                params.principal,
                times,
                roleARNs
            );
            var enc = new Buffer(assertion).toString('base64');

            res.type('html').send(
                `
        <html>
          <script nonce="` +
                    req.headers.rid +
                    `" type="text/javascript">
            window.onload = function() {document.awssaml.submit();}
          </script>
          <body>
            <form name="awssaml" method="post" action="https://signin.aws.amazon.com/saml">
              <input type="hidden" name="SAMLResponse" value="${enc}" />
              <div class="d-loader is-xlarge loader-position"></div>
            </form>
          </body>
        </html>
      `
            );
        }
    });
}

function getMetadata(req, res) {
    const admin = req.url.toLowerCase().indexOf('admin') > -1;
    var sso = admin ? ADMINSSO : DEVSSO;
    const metadata = sso.makeMetadata();
    res.type('xml').send(metadata);
}

module.exports.getMetadata = getMetadata;
module.exports.awsLogin = awsLogin;
// For testing
module.exports.LIBS = LIBS;
