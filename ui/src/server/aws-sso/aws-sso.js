// http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html
// http://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_saml.html
'use strict';

const LIBS = {
    async: require('async'),
    crypto: require('crypto'),
    fs: require('fs'),
    s3: require('../services/s3Service'),
    xmlcrypto: require('xml-crypto'),
};

const region = process.env.REGION || 'us-west-2';
const environment = process.env.ENVIRONMENT || 'stage';
const bucket = 'oath-athenz-ui-data-' + environment + '-' + region;

const debug = require('debug')('AthenzUI:server:aws-sso:aws-sso');

const ASSERTION_TMPL = `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="==RESPONSEID==" Version="2.0" IssueInstant="==NOW==" Destination="https://signin.aws.amazon.com/saml">
  <saml:Issuer>https://ui.athenz.ouroath.com/aws/sso</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="==ASSERTIONID==" Version="2.0" IssueInstant="==NOW==">
    <saml:Issuer>https://ui.athenz.ouroath.com/aws/sso</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier="urn:amazon:webservices" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">==USERNAME==</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="==EXPIRES==" Recipient="https://signin.aws.amazon.com/saml"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="==STARTS==" NotOnOrAfter="==EXPIRES==">
      <saml:AudienceRestriction>
        <saml:Audience>urn:amazon:webservices</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="==NOW==" SessionNotOnOrAfter="==EXPIRES==">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">==USERNAME==</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">==ROLES==</saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

const ROLE_TMPL =
    '<saml:AttributeValue xsi:type="xs:string">==ROLEARN==, arn:aws:iam::==ACCOUNT==:saml-provider/athenz</saml:AttributeValue>';

function makeID() {
    return LIBS.crypto.randomBytes(32).toString('hex');
}

function formatDate(date) {
    var str = date.toISOString();
    // we don't need the milliseconds
    return str.replace(/\.\d\d\dZ$/, 'Z');
}

function makeRole(ssotype, roleARN) {
    var account = roleARN.split(':')[4];
    var xml = ROLE_TMPL.replace(/==ROLEARN==/g, roleARN);
    xml = xml.replace(/==ACCOUNT==/g, account);
    return xml;
}

function signAssertion(privateKey, xml) {
    const sig = new LIBS.xmlcrypto.SignedXml();
    const assertionPath =
        "/*[local-name()='Response']/*[local-name()='Assertion']";
    const issuerPath = assertionPath + "/*[local-name()='Issuer']";
    sig.addReference(
        assertionPath,
        [
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
            'http://www.w3.org/2001/10/xml-exc-c14n#',
        ],
        'http://www.w3.org/2000/09/xmldsig#sha1'
    );
    sig.signingKey = privateKey;
    sig.computeSignature(xml, {
        prefix: 'ds',
        location: { reference: issuerPath, action: 'after' },
    });
    return sig.getSignedXml();
}

function SSO(type) {
    var privateKey;
    var metadata;
    var ssoObj = this;

    var serviceFQN =
        process.env._POD_DOMAIN_NAME + '.' + process.env._POD_SERVICE_NAME;
    if (serviceFQN === 'athenz.ui' || serviceFQN === 'sys.auth.ui') {
        LIBS.async.waterfall(
            [
                function (taskDone) {
                    LIBS.s3.getContent(bucket, 'sso_x509_key', (err, pk) => {
                        if (err) {
                            taskDone(err);
                        } else {
                            privateKey = pk.trim();
                            taskDone(null);
                        }
                    });
                },
                function (taskDone) {
                    LIBS.s3.getContent(bucket, 'sso_metadata_xml', (err, m) => {
                        if (err) {
                            taskDone(err);
                        } else {
                            metadata = m.trim();
                            taskDone(null);
                        }
                    });
                },
            ],
            function (err) {
                if (err) {
                    debug(
                        '[AWS-SSO] Unable to obtain data from S3, error: %o',
                        err
                    );
                    throw err;
                } else {
                    ssoObj.type = type;
                    ssoObj.privateKey = privateKey;
                    ssoObj.metadata = metadata;
                }
            }
        );
    } else {
        LIBS.async.waterfall(
            [
                function (taskDone) {
                    LIBS.fs.readFile(
                        process.env.HOME + '/ssl/sso_x509_key',
                        'utf8',
                        (err, pk) => {
                            if (err) {
                                taskDone(err);
                            } else {
                                privateKey = pk.trim();
                                taskDone(null);
                            }
                        }
                    );
                },
                function (taskDone) {
                    LIBS.fs.readFile(
                        process.env.HOME + '/ssl/sso_metadata_xml',
                        'utf8',
                        (err, m) => {
                            if (err) {
                                taskDone(err);
                            } else {
                                metadata = m.trim();
                                taskDone(null);
                            }
                        }
                    );
                },
            ],
            function (err) {
                if (err) {
                    debug(
                        '[AWS-SSO] Unable to obtain data from local files, error: %o',
                        err
                    );
                    // Not throwing err deliberately, to function without sso in omega
                    // throw err;
                } else {
                    ssoObj.type = type;
                    ssoObj.privateKey = privateKey;
                    ssoObj.metadata = metadata;
                }
            }
        );
    }
}

SSO.prototype.makeMetadata = function makeMetadata() {
    return this.metadata;
};

// times.now {Date} when to consider "right now"
// times.starts {Date} when session starts being active
// times.expires {Date} when session stops being active
SSO.prototype.makeAssertion = function makeAssertion(
    username,
    times,
    roleARNs
) {
    if (!times.now) {
        times.now = new Date();
    }
    if (!times.starts) {
        // default to 10 seconds ago
        times.starts = new Date(times.now.getTime() - 10 * 1000);
    }
    if (!times.expires) {
        // default to 30 minutes
        times.expires = new Date(times.now.getTime() + 30 * 60 * 1000);
    }
    let responseID = makeID();
    let assertionID = makeID();
    let rolesXML = roleARNs
        .map((arn) => {
            return makeRole(this.type, arn);
        })
        .join('');
    let xml = ASSERTION_TMPL.replace(/==RESPONSEID==/g, responseID);
    xml = xml.replace(/==ASSERTIONID==/g, assertionID);
    xml = xml.replace(/==USERNAME==/g, username);
    xml = xml.replace(/==ROLES==/g, rolesXML);
    xml = xml.replace(/==NOW==/g, formatDate(times.now));
    xml = xml.replace(/==STARTS==/g, formatDate(times.starts));
    xml = xml.replace(/==EXPIRES==/g, formatDate(times.expires));
    return signAssertion(this.privateKey, xml);
};

module.exports.SSO = SSO;
