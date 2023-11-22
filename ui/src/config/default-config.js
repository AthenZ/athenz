/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

const config = {
    local: {
        timeZone: 'America/Los_Angeles',
        language: 'en-US',
        zms: process.env.ZMS_SERVER_URL || 'https://localhost:4443/zms/v1/',
        zmsLoginUrl:
            process.env.ZMS_LOGIN_URL || 'https://localhost:4443/zms/v1/',
        zmsConnectSrcUrl:
            process.env.ZMS_CONNECT_SRC_URL || 'https://localhost:4443',
        msd: process.env.MSD_LOGIN_URL || 'https://localhost:4443/msd/v1/',
        zts: process.env.ZTS_LOGIN_URL || 'https://localhost:4443/zts/v1/',
        ums: process.env.UMS_LOGIN_URL || 'https://localhost:4443/ums/v1/',
        authHeader: 'Athenz-Principal-Auth',
        strictSSL: false,
        user: 'ui-server',
        athenzDomainService:
            process.env.UI_DOMAIN_SERVICE || 'athenz.ui-server',
        authKeyVersion: process.env.UI_SERVICE_KEY_VERSION || '0',
        envLabel: 'local',
        userData: (user) => {
            return {
                userIcon: '/static/athenz-logo.png',
                userMail: '',
                userLink: {
                    title: 'User Link',
                    url: '',
                    target: '_blank',
                },
            };
        },
        headerLinks: [
            { title: 'Website', url: 'http://www.athenz.io', target: '_blank' },
            {
                title: 'Getting Started',
                url: 'https://github.com/AthenZ/athenz/blob/master/README.md',
                target: '_blank',
            },
            {
                title: 'Documentation',
                url: 'https://github.com/AthenZ/athenz/blob/master/README.md',
                target: '_blank',
            },
            {
                title: 'GitHub',
                url: 'https://github.com/AthenZ/athenz',
                target: '_blank',
            },
            {
                title: 'Suggest',
                url: 'https://github.com/AthenZ/athenz/issues',
                target: '_blank',
            },
            {
                title: 'Contact Us',
                url: 'https://www.athenz.io/contact.html',
                target: '_blank',
            },
            {
                title: 'Blog',
                url: 'https://www.tumblr.com/blog/athenz-security',
                target: '_blank',
            },
            { title: 'Logout', url: '/login', target: '' },
        ],
        productMasterLink: {
            title: 'Product ID',
            url: '',
            target: '_blank',
        },
        servicePageConfig: {
            keyCreationLink: {
                title: 'Key Creation',
                url: 'https://yahoo.github.io/athenz/site/reg_service_guide/#key-generation',
                target: '_blank',
            },
            keyCreationMessage:
                'Instances bootstrapped using Athenz Identity Providers can get Service Identity X.509 certificates automatically.',
        },
        cookieName: 'Athenz-Principal-Auth',
        cookieMaxAge: 60 * 60 * 1000,
        loginPath: '/login',
        uiKeyPath: process.env.UI_CERT_KEY_PATH || 'keys/ui_key.pem',
        uiCertPath: process.env.UI_CERT_PATH || 'keys/ui_cert.pem',
        userFileName: 'users_data.json',
        userFilePath: process.env.UI_CONF_PATH || 'src/config',
        cookieSession:
            process.env.UI_SESSION_SECRET_PATH || 'keys/cookie-session',
        userDomain: 'user',
        userDomains: 'user,unix',
        port: parseInt(process.env.PORT, 10) || 443,
        allProviders: [
            {
                id: 'aws_instance_launch_provider',
                name: 'AWS EC2/EKS/Fargate launches instances for the service',
            },
        ],
        createDomainMessage:
            'Athenz top level domain creation is manual. \n Please connect with your system administrator to create top level domains. \n',
        cspReportUri: '',
        cspImgSrc: [],
        formAction: [],
        allPrefixes: [
            {
                name: 'AWS',
                prefix: ':role.aws',
            },
        ],
        statusPath: process.env.UI_SESSION_SECRET_PATH || 'keys/cookie-session',
        featureFlag: true,
        pageFeatureFlag: {
            microsegmentation: {
                policyValidation: true,
            },
            roleGroupReview: {
                roleGroupReviewFeatureFlag: true,
            },
        },
        serviceHeaderLinks: [
            {
                description:
                    'Here you can add / see instances which can not obtain Athenz identity because of limitations, but would be associated with your service.',
                url: '',
                target: '_blank',
            },
            {
                description:
                    'Here you can see instances which are running with this service identity',
                url: '',
                target: '_blank',
            },
        ],
        templates: ['openhouse'],
        msdAuthHeaderPath:
            '/var/lib/sia/tokens/msd-api-access/msd-api-access-token',
        numberOfRetry: 2,
        serverCipherSuites:
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    },
    unittest: {
        zmsConnectSrcUrl: 'https://localhost:4443',
        athenzDomainService: 'athenz.unit-test',
        authKeyVersion: '1',
        envLabel: 'unittest',
        cookieName: 'Athenz-Principal-Auth',
        cookieMaxAge: 60 * 60 * 1000,
        loginPath: '/login',
        userDomain: 'user',
        user: 'test',
        authHeader: 'Athenz-Principal-Auth',
        cspReportUri: 'https://athenz.io/csp',
        cspImgSrc: 'https://athenz.com',
        allPrefixes: [
            {
                name: 'AWS',
                prefix: ':role.aws',
            },
        ],
        featureFlag: true,
        pageFeatureFlag: {
            microsegmentation: {
                policyValidation: true,
            },
            roleGroupReview: {
                roleGroupReviewFeatureFlag: true,
            },
        },
        serviceHeaderLinks: [
            {
                description:
                    'Here you can add / see instances which can not obtain Athenz identity because of limitations, but would be associated with your service.',
                url: '',
                target: '_blank',
            },
            {
                description:
                    'Here you can see instances which are running with this service identity',
                url: '',
                target: '_blank',
            },
        ],
        templates: ['openhouse'],
        msdAuthHeaderPath:
            '/var/lib/sia/tokens/msd-api-access/msd-api-access-token',
        numberOfRetry: 2,
        serverCipherSuites:
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    },
};

module.exports = function () {
    let env = process.env.APP_ENV ? process.env.APP_ENV : 'local';
    const c = config[env];
    c.env = env;
    return c;
};
