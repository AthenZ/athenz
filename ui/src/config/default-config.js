/*
 * Copyright 2020 Verizon Media
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
                url: 'https://github.com/yahoo/athenz/blob/master/README.md',
                target: '_blank',
            },
            {
                title: 'Documentation',
                url: 'https://github.com/yahoo/athenz/blob/master/README.md',
                target: '_blank',
            },
            {
                title: 'GitHub',
                url: 'https://github.com/yahoo/athenz',
                target: '_blank',
            },
            {
                title: 'Suggest',
                url: 'https://github.com/yahoo/athenz/issues',
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
                url:
                    'https://yahoo.github.io/athenz/site/reg_service_guide/#key-generation',
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
        cspImgSrc: '',
        statusPath: process.env.UI_SESSION_SECRET_PATH || 'keys/cookie-session',
    },
    unittest: {
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
    },
};

module.exports = function() {
    let env = process.env.APP_ENV ? process.env.APP_ENV : 'local';
    const c = config[env];
    c.env = env;
    return c;
};
