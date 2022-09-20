'use strict';
// "development" is least-privileged non-production
// "athenz.ui" is most-privileged non-production
// "sys.auth.ui" is production (most-privileged by definition)

const homedir = require('os').homedir();

const config = {
    local: {
        envLabel: 'local',
        zms:
            process.env.LOCAL_ZMS_API ||
            'https://dev.zms.athens.yahoo.com:4443/zms/v1/',
        zts:
            process.env.LOCAL_ZTS_API ||
            'https://dev.zts.athens.yahoo.com:4443/zts/v1/',
        msd:
            process.env.LOCAL_MSD_API ||
            'https://dev.api.msd.ouryahoo.com:4443/msd/v1/',
        defaultUser: process.env.USER,
        okta: {
            keyGroup: 'athenz.dev',
            key: 'athenz.dev.ui.okta',
        },
        cookie: {
            keyGroup: 'athenz.dev',
            key: 'athenz.dev.ui.cookie',
        },
        serverKey: {
            keyGroup: 'athens.aws-stage.certs',
            key: 'athens.server.ui.aws_nonprod_private_key',
        },
        serverCert: {
            keyGroup: 'athens.aws-stage.certs',
            key: 'athens.server.ui.aws_nonprod_cert',
        },
        port: parseInt(process.env.PORT, 10) || 443,
        oktaEnv: process.env.LOCAL_OKTA_ENV || 'qa',
        oktaClientId:
            process.env.LOCAL_OKTA_CLIENT_ID || '0oafqyabcyG7kxhXm0h7',
        oktaCookieDomain:
            process.env.LOCAL_OKTA_COOKIE_DOMAIN ||
            'local-ui.athenz.ouryahoo.com',
        userKey: '/.athenz/key',
        userCert: '/.athenz/cert',
        athenzDomainService: 'athenz.dev.devui',
        awsDBDomain: 'athenz',
        awsDBRole: 'athenz.zts.audit-log-reader',
        serverURL: 'https://local-ui.athenz.ouryahoo.com',
        athenzPrivateKeyPath: homedir + '/ssl/keys/local.key.pem',
        athenzX509CertPath: homedir + '/ssl/certs/local.cert.pem',
        akamaiPath: homedir + '/ssl/certs/local.cert.pem',
        statusPath: homedir + '/ssl/certs/local.cert.pem',
        awsYanisDomain: 'athenz',
        awsYanisRole: 'athenz.yanis',
        userFilePath: 'oath-athenz-yanis-stage-us-west-2',
        userFileName: 'users_data.json',
        userDomains: 'user,unix,ygrid',
        allowCname: true,
        allowedDomains: ['local-ui.athenz.ouryahoo.com'],
        userData: (user) => {
            let firstCharUserId = user.charAt(0);
            return {
                userIcon: `https://directory.ouryahoo.com/emp_photos/vzm/${firstCharUserId}/${user}.jpg`,
                userMail: `${user}@yahooinc.com`,
                userLink: {
                    title: 'User Profile',
                    url: `https://thestreet.ouryahoo.com/thestreet/directory?email=${user}@yahooinc.com`,
                    target: '_blank',
                },
            };
        },
        headerLinks: [
            {
                title: 'User Guide',
                url: 'https://git.ouryahoo.com/pages/athens/athenz-guide/',
                target: '_blank',
            },
            {
                title: 'Follow us on Street',
                url: 'https://thestreet.ouryahoo.com/thestreet/ls/community/athenz',
                target: '_blank',
            },
            {
                title: 'Support',
                url: 'https://jira.ouryahoo.com/secure/CreateIssue.jspa?pid=10388&issuetype=10100',
                target: '_blank',
            },
        ],
        productMasterLink: {
            title: 'Product ID',
            url: 'https://productmaster.ouryahoo.com/engineering/product/',
            target: '_blank',
        },
        servicePageConfig: {
            keyCreationLink: {
                title: 'Key Creation',
                url: 'https://git.ouryahoo.com/pages/athens/athenz-guide/manual_service_registration/#key-generation',
                target: '_blank',
            },
            keyCreationMessage:
                'Instances bootstrapped using Athenz Identity Providers ( Calypso, AWS, Omega to name a few ) can get Service Identity X.509 certificates automatically.',
        },
        allProviders: [
            {
                id: 'aws_instance_launch_provider',
                name: 'AWS EC2/EKS/Fargate launches instances for the service',
            },
            {
                id: 'openstack_instance_launch_provider',
                name: 'Openstack/OWS launches instances for the service',
            },
            {
                id: 'aws_ecs_instance_launch_provider',
                name: 'AWS ECS launches containers for the service',
            },
            {
                id: 'aws_lambda_instance_launch_provider',
                name: 'AWS Lambda runs code for the service',
            },
            {
                id: 'vespa_instance_launch_provider',
                name: 'Vespa launches application for the service',
            },
            {
                id: 'k8s_omega_instance_launch_provider',
                name: 'Kubernetes (Omega) launches instances for the service',
            },
            {
                id: 'zts_instance_launch_provider',
                name: 'Allow ZTS as an identity provider for the service',
            },
            {
                id: 'azure_instance_launch_provider',
                name: 'Azure VM launches instances for the service',
            },
            {
                id: 'ybiip_instance_launch_provider',
                name: 'YBIIP launches instances for the service',
            },
            {
                id: 'secureboot_instance_launch_provider',
                name: 'SecureBoot launches instances for the service',
            },
        ],
        createDomainMessage:
            'Athenz top level domain creation will be manual until it is integrated with an updated Yahoo product taxonomy. \n If your product does not have a top level domain already registered in Athenz, you can file a JIRA ticket in the JIRA ATHENS queue. \n Please provide the Product ID for your product from "Product Master", a short and descriptive domain name and list of administrators identified by their Okta Short IDs. \n',
        cspReportUri: 'https://csp.yahoo.com/beacon/csp?src=athenz',
        cspImgSrc: ['https://directory.ouryahoo.com'],
        formAction: [
            'https://signin.aws.amazon.com/saml',
            'https://console.aws.amazon.com/console/home',
        ],
        allPrefixes: [
            {
                name: 'AWS',
                prefix: ':role.aws',
            },
            {
                name: 'Calypso',
                prefix: ':role.ums',
            },
            {
                name: 'CKMS',
                prefix: ':role.paranoids.ppse.ckms.ykeykey_',
            },
            {
                name: 'Yamas',
                prefix: ':role.yamas.tenancy',
            },
            {
                name: 'Kubernetes',
                prefix: ':role.k8s',
            },
            {
                name: 'Sherpa',
                prefix: ':role.sherpa.tenancy',
            },
            {
                name: 'Microsegmentation',
                prefix: ':role.acl',
            },
            {
                name: 'Halo',
                prefix: ':role.halo',
            },
        ],
        featureFlag: true,
        pageFeatureFlag: {
            microsegmentation: {
                policyValidation: true,
            },
        },
        serviceHeaderLinks: [
            {
                description:
                    'Here you can add / see instances which can not obtain Athenz identity because of limitations, but would be associated with your service.',
                url: 'http://yo/service-instances',
                target: '_blank',
            },
            {
                description:
                    'Here you can see instances which are running with this service identity',
                url: 'http://yo/service-instances',
                target: '_blank',
            },
        ],
        templates: ['openhouse', 'owshome'],
        msdAuthHeaderPath: '/ssl/tokens/msd-api-access/msd-api-access-token',
        numberOfRetry: 2,
    },
    development: {
        envLabel: 'Development',
        zms: 'https://dev.zms.athens.yahoo.com:4443/zms/v1/',
        zts: 'https://zts.athenz.ouroath.com:4443/zts/v1/',
        msd: 'https://dev.api.msd.ouryahoo.com:4443/msd/v1/',
        okta: {
            keyGroup: 'athenz.dev',
            key: 'athenz.dev.ui.okta',
        },
        cookie: {
            keyGroup: 'athenz.dev',
            key: 'athenz.dev.ui.cookie',
        },
        serverKey: {
            keyGroup: 'athens.aws-stage.certs',
            key: 'athens.server.ui.aws_nonprod_private_key',
        },
        serverCert: {
            keyGroup: 'athens.aws-stage.certs',
            key: 'athens.server.ui.aws_nonprod_cert',
        },
        port: 443,
        oktaEnv: 'qa',
        oktaClientId: '0oafqyabcyG7kxhXm0h7',
        oktaCookieDomain: 'dev-ui.athenz.ouryahoo.com',
        athenzDomainService: 'athenz.k8s.athenz-ui-development',
        akamaiPath: '/home/y/share/node/manhattan_app/akamai',
        statusPath: '/home/y/share/node/manhattan_app/status.html',
        awsDBDomain: 'athenz',
        awsDBRole: 'athenz.zts.audit-log-reader',
        serverURL: 'https://dev-ui.athenz.ouryahoo.com',
        athenzPrivateKeyPath: '/var/run/athenz/service.key.pem',
        athenzX509CertPath: '/var/run/athenz/service.cert.pem',
        awsYanisDomain: 'athenz',
        awsYanisRole: 'athenz.yanis',
        userFilePath: 'oath-athenz-yanis-stage-us-west-2',
        userFileName: 'users_data.json',
        userDomains: 'user,unix,ygrid',
        userData: (user) => {
            let firstCharUserId = user.charAt(0);
            return {
                userIcon: `https://directory.ouryahoo.com/emp_photos/vzm/${firstCharUserId}/${user}.jpg`,
                userMail: `${user}@yahooinc.com`,
                userLink: {
                    title: 'User Profile',
                    url: `https://thestreet.ouryahoo.com/thestreet/directory?email=${user}@yahooinc.com`,
                    target: '_blank',
                },
            };
        },
        headerLinks: [
            {
                title: 'User Guide',
                url: 'https://git.ouryahoo.com/pages/athens/athenz-guide/',
                target: '_blank',
            },
            {
                title: 'Follow us on Street',
                url: 'https://thestreet.ouryahoo.com/thestreet/ls/community/athenz',
                target: '_blank',
            },
            {
                title: 'Support',
                url: 'https://jira.ouryahoo.com/secure/CreateIssue.jspa?pid=10388&issuetype=10100',
                target: '_blank',
            },
        ],
        productMasterLink: {
            title: 'Product ID',
            url: 'https://productmaster.ouryahoo.com/engineering/product/',
            target: '_blank',
        },
        servicePageConfig: {
            keyCreationLink: {
                title: 'Key Creation',
                url: 'https://git.ouryahoo.com/pages/athens/athenz-guide/manual_service_registration/#key-generation',
                target: '_blank',
            },
            keyCreationMessage:
                'Instances bootstrapped using Athenz Identity Providers ( Calypso, AWS, Omega to name a few ) can get Service Identity X.509 certificates automatically.',
        },
        allProviders: [
            {
                id: 'aws_instance_launch_provider',
                name: 'AWS EC2/EKS/Fargate launches instances for the service',
            },
            {
                id: 'openstack_instance_launch_provider',
                name: 'Openstack/OWS launches instances for the service',
            },
            {
                id: 'aws_ecs_instance_launch_provider',
                name: 'AWS ECS launches containers for the service',
            },
            {
                id: 'aws_lambda_instance_launch_provider',
                name: 'AWS Lambda runs code for the service',
            },
            {
                id: 'vespa_instance_launch_provider',
                name: 'Vespa launches application for the service',
            },
            {
                id: 'k8s_omega_instance_launch_provider',
                name: 'Kubernetes (Omega) launches instances for the service',
            },
            {
                id: 'zts_instance_launch_provider',
                name: 'Allow ZTS as an identity provider for the service',
            },
            {
                id: 'azure_instance_launch_provider',
                name: 'Azure VM launches instances for the service',
            },
            {
                id: 'ybiip_instance_launch_provider',
                name: 'YBIIP launches instances for the service',
            },
            {
                id: 'secureboot_instance_launch_provider',
                name: 'SecureBoot launches instances for the service',
            },
        ],
        createDomainMessage:
            'Athenz top level domain creation will be manual until it is integrated with an updated Yahoo product taxonomy. \n If your product does not have a top level domain already registered in Athenz, you can file a JIRA ticket in the JIRA ATHENS queue. \n Please provide the Product ID for your product from "Product Master", a short and descriptive domain name and list of administrators identified by their Okta Short IDs. \n',
        cspReportUri: 'https://csp.yahoo.com/beacon/csp?src=athenz',
        cspImgSrc: ['https://directory.ouryahoo.com'],
        formAction: [
            'https://signin.aws.amazon.com/saml',
            'https://console.aws.amazon.com/console/home',
        ],
        allPrefixes: [
            {
                name: 'AWS',
                prefix: ':role.aws',
            },
            {
                name: 'Calypso',
                prefix: ':role.ums',
            },
            {
                name: 'CKMS',
                prefix: ':role.paranoids.ppse.ckms.ykeykey_',
            },
            {
                name: 'Yamas',
                prefix: ':role.yamas.tenancy',
            },
            {
                name: 'Kubernetes',
                prefix: ':role.k8s',
            },
            {
                name: 'Sherpa',
                prefix: ':role.sherpa.tenancy',
            },
            {
                name: 'Microsegmentation',
                prefix: ':role.acl',
            },
            {
                name: 'Halo',
                prefix: ':role.halo',
            },
        ],
        featureFlag: true,
        pageFeatureFlag: {
            microsegmentation: {
                policyValidation: true,
            },
        },
        serviceHeaderLinks: [
            {
                description:
                    'Here you can add / see instances which can not obtain Athenz identity because of limitations, but would be associated with your service.',
                url: 'http://yo/service-instances',
                target: '_blank',
            },
            {
                description:
                    'Here you can see instances which are running with this service identity',
                url: 'http://yo/service-instances',
                target: '_blank',
            },
        ],
        templates: ['openhouse', 'owshome'],
        msdAuthHeaderPath: '/var/run/athenz/tokens/athenz/msd-api-access-token',
        numberOfRetry: 2,
    },
    pullrequest: {
        envLabel: 'Pullrequest',
        zms: 'https://dev.zms.athens.yahoo.com:4443/zms/v1/',
        zts: 'https://stage.zts.athenz.ouroath.com:4443/zts/v1/',
        msd: 'https://dev.api.msd.ouryahoo.com:4443/msd/v1/',
        okta: {
            keyGroup: 'athenz.dev',
            key: 'athenz.dev.ui.okta',
        },
        cookie: {
            keyGroup: 'athenz.dev',
            key: 'athenz.dev.ui.cookie',
        },
        serverKey: {
            keyGroup: 'athens.aws-stage.certs',
            key: 'athens.server.ui.aws_nonprod_private_key',
        },
        serverCert: {
            keyGroup: 'athens.aws-stage.certs',
            key: 'athens.server.ui.aws_nonprod_cert',
        },
        port: 443,
        oktaEnv: 'qa',
        oktaClientId: '0oafqyabcyG7kxhXm0h7',
        oktaCookieDomain: 'pullrequest-ui.athenz.ouryahoo.com',
        athenzDomainService: 'athenz.k8s.athenz-ui-pullrequest',
        akamaiPath: '/home/y/share/node/manhattan_app/akamai',
        statusPath: '/home/y/share/node/manhattan_app/status.html',
        awsDBDomain: 'athenz',
        awsDBRole: 'athenz.zts.audit-log-reader',
        serverURL: 'https://pullrequest-ui.athenz.ouryahoo.com',
        athenzPrivateKeyPath: '/var/run/athenz/service.key.pem',
        athenzX509CertPath: '/var/run/athenz/service.cert.pem',
        awsYanisDomain: 'athenz',
        awsYanisRole: 'athenz.yanis',
        userFilePath: 'oath-athenz-yanis-stage-us-west-2',
        userFileName: 'users_data.json',
        userDomains: 'user,unix,ygrid',
        userData: (user) => {
            let firstCharUserId = user.charAt(0);
            return {
                userIcon: `https://directory.ouryahoo.com/emp_photos/vzm/${firstCharUserId}/${user}.jpg`,
                userMail: `${user}@yahooinc.com`,
                userLink: {
                    title: 'User Profile',
                    url: `https://thestreet.ouryahoo.com/thestreet/directory?email=${user}@yahooinc.com`,
                    target: '_blank',
                },
            };
        },
        headerLinks: [
            {
                title: 'User Guide',
                url: 'https://git.ouryahoo.com/pages/athens/athenz-guide/',
                target: '_blank',
            },
            {
                title: 'Follow us on Street',
                url: 'https://thestreet.ouryahoo.com/thestreet/ls/community/athenz',
                target: '_blank',
            },
            {
                title: 'Support',
                url: 'https://jira.ouryahoo.com/secure/CreateIssue.jspa?pid=10388&issuetype=10100',
                target: '_blank',
            },
        ],
        productMasterLink: {
            title: 'Product ID',
            url: 'https://productmaster.ouryahoo.com/engineering/product/',
            target: '_blank',
        },
        servicePageConfig: {
            keyCreationLink: {
                title: 'Key Creation',
                url: 'https://git.ouryahoo.com/pages/athens/athenz-guide/manual_service_registration/#key-generation',
                target: '_blank',
            },
            keyCreationMessage:
                'Instances bootstrapped using Athenz Identity Providers ( Calypso, AWS, Omega to name a few ) can get Service Identity X.509 certificates automatically.',
        },
        allProviders: [
            {
                id: 'aws_instance_launch_provider',
                name: 'AWS EC2/EKS/Fargate launches instances for the service',
            },
            {
                id: 'openstack_instance_launch_provider',
                name: 'Openstack/OWS launches instances for the service',
            },
            {
                id: 'aws_ecs_instance_launch_provider',
                name: 'AWS ECS launches containers for the service',
            },
            {
                id: 'aws_lambda_instance_launch_provider',
                name: 'AWS Lambda runs code for the service',
            },
            {
                id: 'vespa_instance_launch_provider',
                name: 'Vespa launches application for the service',
            },
            {
                id: 'k8s_omega_instance_launch_provider',
                name: 'Kubernetes (Omega) launches instances for the service',
            },
            {
                id: 'zts_instance_launch_provider',
                name: 'Allow ZTS as an identity provider for the service',
            },
            {
                id: 'azure_instance_launch_provider',
                name: 'Azure VM launches instances for the service',
            },
            {
                id: 'ybiip_instance_launch_provider',
                name: 'YBIIP launches instances for the service',
            },
            {
                id: 'secureboot_instance_launch_provider',
                name: 'SecureBoot launches instances for the service',
            },
        ],
        createDomainMessage:
            'Athenz top level domain creation will be manual until it is integrated with an updated Yahoo product taxonomy. \n If your product does not have a top level domain already registered in Athenz, you can file a JIRA ticket in the JIRA ATHENS queue. \n Please provide the Product ID for your product from "Product Master", a short and descriptive domain name and list of administrators identified by their Okta Short IDs. \n',
        cspReportUri: 'https://csp.yahoo.com/beacon/csp?src=athenz',
        cspImgSrc: ['https://directory.ouryahoo.com'],
        formAction: [
            'https://signin.aws.amazon.com/saml',
            'https://console.aws.amazon.com/console/home',
        ],
        allPrefixes: [
            {
                name: 'AWS',
                prefix: ':role.aws',
            },
            {
                name: 'Calypso',
                prefix: ':role.ums',
            },
            {
                name: 'CKMS',
                prefix: ':role.paranoids.ppse.ckms.ykeykey_',
            },
            {
                name: 'Yamas',
                prefix: ':role.yamas.tenancy',
            },
            {
                name: 'Kubernetes',
                prefix: ':role.k8s',
            },
            {
                name: 'Sherpa',
                prefix: ':role.sherpa.tenancy',
            },
            {
                name: 'Microsegmentation',
                prefix: ':role.acl',
            },
            {
                name: 'Halo',
                prefix: ':role.halo',
            },
        ],
        featureFlag: true,
        pageFeatureFlag: {
            microsegmentation: {
                policyValidation: true,
            },
        },
        serviceHeaderLinks: [
            {
                description:
                    'Here you can add / see instances which can not obtain Athenz identity because of limitations, but would be associated with your service.',
                url: 'http://yo/service-instances',
                target: '_blank',
            },
            {
                description:
                    'Here you can see instances which are running with this service identity',
                url: 'http://yo/service-instances',
                target: '_blank',
            },
        ],
        templates: ['openhouse', 'owshome'],
        msdAuthHeaderPath: '/var/run/athenz/tokens/athenz/msd-api-access-token',
        numberOfRetry: 2,
    },
    'athenz.ui': {
        envLabel: 'Staging',
        zms: 'https://stage.zms.athenz.ouroath.com:4443/zms/v1',
        zts: 'https://zts.athenz.ouroath.com:4443/zts/v1/',
        msd: 'https://stg-pub.msd.athenz.yahoo.com:443/msd/v1/',
        okta: {
            keyGroup: 'athenz.ui',
            key: 'athenz.ui.okta',
        },
        cookie: {
            keyGroup: 'athenz.ui',
            key: 'athenz.ui.cookie',
        },
        serverKey: {
            keyGroup: 'athenz.ui',
            key: 'athenz.ui.server.key',
        },
        serverCert: {
            keyGroup: 'athenz.ui',
            key: 'athenz.ui.server.cert',
        },
        port: 443,
        oktaEnv: 'prod',
        oktaClientId: '0oa48m26py0XJWzcE1t7',
        oktaCookieDomain: 'stage-ui.athenz.ouroath.com',
        athenzDomainService: 'athenz.ui',
        awsDBDomain: 'athenz',
        awsDBRole: 'athenz.zts.audit-log-reader',
        akamaiPath: '/opt/athenz-ui/status.html',
        statusPath: '/opt/athenz-ui/status.html',
        serverURL: 'https://stage-ui.athenz.ouroath.com',
        athenzPrivateKeyPath: '/var/lib/sia/keys/athenz.ui.key.pem',
        athenzX509CertPath: '/var/lib/sia/certs/athenz.ui.cert.pem',
        awsYanisDomain: 'athenz',
        awsYanisRole: 'athenz.yanis',
        userFilePath: 'oath-athenz-yanis-stage-us-west-2',
        userFileName: 'users_data.json',
        awsSecretsBucketName: 'oath-athenz-ui-data-stage-us-west-2',
        userDomains: 'user,unix,ygrid',
        allowCname: true,
        allowedDomains: [
            'stage-ui.athenz.ouroath.com',
            'stage-ui.athenz.ouryahoo.com',
        ],
        userData: (user) => {
            let firstCharUserId = user.charAt(0);
            return {
                userIcon: `https://directory.ouryahoo.com/emp_photos/vzm/${firstCharUserId}/${user}.jpg`,
                userMail: `${user}@yahooinc.com`,
                userLink: {
                    title: 'User Profile',
                    url: `https://thestreet.ouryahoo.com/thestreet/directory?email=${user}@yahooinc.com`,
                    target: '_blank',
                },
            };
        },
        headerLinks: [
            {
                title: 'User Guide',
                url: 'https://git.ouryahoo.com/pages/athens/athenz-guide/',
                target: '_blank',
            },
            {
                title: 'Follow us on Street',
                url: 'https://thestreet.ouryahoo.com/thestreet/ls/community/athenz',
                target: '_blank',
            },
            {
                title: 'Support',
                url: 'https://jira.ouryahoo.com/secure/CreateIssue.jspa?pid=10388&issuetype=10100',
                target: '_blank',
            },
        ],
        productMasterLink: {
            title: 'Product ID',
            url: 'https://productmaster.ouryahoo.com/engineering/product/',
            target: '_blank',
        },
        servicePageConfig: {
            keyCreationLink: {
                title: 'Key Creation',
                url: 'https://git.ouryahoo.com/pages/athens/athenz-guide/manual_service_registration/#key-generation',
                target: '_blank',
            },
            keyCreationMessage:
                'Instances bootstrapped using Athenz Identity Providers ( Calypso, AWS, Omega to name a few ) can get Service Identity X.509 certificates automatically.',
        },
        allProviders: [
            {
                id: 'aws_instance_launch_provider',
                name: 'AWS EC2/EKS/Fargate launches instances for the service',
            },
            {
                id: 'openstack_instance_launch_provider',
                name: 'Openstack/OWS launches instances for the service',
            },
            {
                id: 'aws_ecs_instance_launch_provider',
                name: 'AWS ECS launches containers for the service',
            },
            {
                id: 'aws_lambda_instance_launch_provider',
                name: 'AWS Lambda runs code for the service',
            },
            {
                id: 'vespa_instance_launch_provider',
                name: 'Vespa launches application for the service',
            },
            {
                id: 'k8s_omega_instance_launch_provider',
                name: 'Kubernetes (Omega) launches instances for the service',
            },
            {
                id: 'zts_instance_launch_provider',
                name: 'Allow ZTS as an identity provider for the service',
            },
            {
                id: 'azure_instance_launch_provider',
                name: 'Azure VM launches instances for the service',
            },
            {
                id: 'ybiip_instance_launch_provider',
                name: 'YBIIP launches instances for the service',
            },
            {
                id: 'secureboot_instance_launch_provider',
                name: 'SecureBoot launches instances for the service',
            },
        ],
        createDomainMessage:
            'Athenz top level domain creation will be manual until it is integrated with an updated Yahoo product taxonomy. \n If your product does not have a top level domain already registered in Athenz, you can file a JIRA ticket in the JIRA ATHENS queue. \n Please provide the Product ID for your product from "Product Master", a short and descriptive domain name and list of administrators identified by their Okta Short IDs. \n',
        cspReportUri: 'https://csp.yahoo.com/beacon/csp?src=athenz',
        cspImgSrc: ['https://directory.ouryahoo.com'],
        formAction: [
            'https://signin.aws.amazon.com/saml',
            'https://console.aws.amazon.com/console/home',
        ],
        allPrefixes: [
            {
                name: 'AWS',
                prefix: ':role.aws',
            },
            {
                name: 'Calypso',
                prefix: ':role.ums',
            },
            {
                name: 'CKMS',
                prefix: ':role.paranoids.ppse.ckms.ykeykey_',
            },
            {
                name: 'Yamas',
                prefix: ':role.yamas.tenancy',
            },
            {
                name: 'Kubernetes',
                prefix: ':role.k8s',
            },
            {
                name: 'Sherpa',
                prefix: ':role.sherpa.tenancy',
            },
            {
                name: 'Microsegmentation',
                prefix: ':role.acl',
            },
            {
                name: 'Halo',
                prefix: ':role.halo',
            },
        ],
        featureFlag: true,
        pageFeatureFlag: {
            microsegmentation: {
                policyValidation: true,
            },
        },
        serviceHeaderLinks: [
            {
                description:
                    'Here you can add / see instances which can not obtain Athenz identity because of limitations, but would be associated with your service.',
                url: 'http://yo/service-instances',
                target: '_blank',
            },
            {
                description:
                    'Here you can see instances which are running with this service identity',
                url: 'http://yo/service-instances',
                target: '_blank',
            },
        ],
        templates: ['openhouse', 'owshome'],
        msdAuthHeaderPath:
            '/var/lib/sia/tokens/msd-api-access/msd-api-access-token',
        numberOfRetry: 2,
    },
    'sys.auth.ui': {
        zms: 'https://zms.athenz.ouroath.com:4443/zms/v1',
        zts: 'https://zts.athenz.ouroath.com:4443/zts/v1/',
        msd: 'https://msd-pub.athenz.yahoo.com:443/msd/v1/',
        okta: {
            keyGroup: 'sys.auth.ui',
            key: 'sys.auth.ui.okta',
        },
        cookie: {
            keyGroup: 'sys.auth.ui',
            key: 'sys.auth.ui.cookie',
        },
        serverKey: {
            keyGroup: 'sys.auth.ui',
            key: 'sys.auth.ui.server.key',
        },
        serverCert: {
            keyGroup: 'sys.auth.ui',
            key: 'sys.auth.ui.server.cert',
        },
        port: 443,
        oktaEnv: 'prod',
        oktaClientId: '0oa454iejb5D2pZDB1t7',
        oktaCookieDomain: 'ui.athenz.ouroath.com',
        athenzDomainService: 'sys.auth.ui',
        awsDBDomain: 'sys.auth',
        awsDBRole: 'sys.auth.zts.audit-log-reader',
        akamaiPath: '/opt/athenz-ui/status.html',
        statusPath: '/opt/athenz-ui/status.html',
        serverURL: 'https://ui.athenz.ouroath.com',
        athenzPrivateKeyPath: '/var/lib/sia/keys/sys.auth.ui.key.pem',
        athenzX509CertPath: '/var/lib/sia/certs/sys.auth.ui.cert.pem',
        awsYanisDomain: 'sys.auth',
        awsYanisRole: 'athenz.yanis',
        userFilePath: 'oath-athenz-yanis-prod-us-west-2',
        userFileName: 'users_data.json',
        awsSecretsBucketName: 'oath-athenz-ui-data-prod-us-west-2',
        userDomains: 'user,unix,ygrid',
        userData: (user) => {
            let firstCharUserId = user.charAt(0);
            return {
                userIcon: `https://directory.ouryahoo.com/emp_photos/vzm/${firstCharUserId}/${user}.jpg`,
                userMail: `${user}@yahooinc.com`,
                userLink: {
                    title: 'User Profile',
                    url: `https://thestreet.ouryahoo.com/thestreet/directory?email=${user}@yahooinc.com`,
                    target: '_blank',
                },
            };
        },
        headerLinks: [
            {
                title: 'User Guide',
                url: 'https://git.ouryahoo.com/pages/athens/athenz-guide/',
                target: '_blank',
            },
            {
                title: 'Follow us on Street',
                url: 'https://thestreet.ouryahoo.com/thestreet/ls/community/athenz',
                target: '_blank',
            },
            {
                title: 'Support',
                url: 'https://jira.ouryahoo.com/secure/CreateIssue.jspa?pid=10388&issuetype=10100',
                target: '_blank',
            },
        ],
        productMasterLink: {
            title: 'Product ID',
            url: 'https://productmaster.ouryahoo.com/engineering/product/',
            target: '_blank',
        },
        servicePageConfig: {
            keyCreationLink: {
                title: 'Key Creation',
                url: 'https://git.ouryahoo.com/pages/athens/athenz-guide/manual_service_registration/#key-generation',
                target: '_blank',
            },
            keyCreationMessage:
                'Instances bootstrapped using Athenz Identity Providers ( Calypso, AWS, Omega to name a few ) can get Service Identity X.509 certificates automatically.',
        },
        allProviders: [
            {
                id: 'aws_instance_launch_provider',
                name: 'AWS EC2/EKS/Fargate launches instances for the service',
            },
            {
                id: 'openstack_instance_launch_provider',
                name: 'Openstack/OWS launches instances for the service',
            },
            {
                id: 'aws_ecs_instance_launch_provider',
                name: 'AWS ECS launches containers for the service',
            },
            {
                id: 'aws_lambda_instance_launch_provider',
                name: 'AWS Lambda runs code for the service',
            },
            {
                id: 'vespa_instance_launch_provider',
                name: 'Vespa launches application for the service',
            },
            {
                id: 'k8s_omega_instance_launch_provider',
                name: 'Kubernetes (Omega) launches instances for the service',
            },
            {
                id: 'zts_instance_launch_provider',
                name: 'Allow ZTS as an identity provider for the service',
            },
            {
                id: 'azure_instance_launch_provider',
                name: 'Azure VM launches instances for the service',
            },
            {
                id: 'ybiip_instance_launch_provider',
                name: 'YBIIP launches instances for the service',
            },
            {
                id: 'secureboot_instance_launch_provider',
                name: 'SecureBoot launches instances for the service',
            },
        ],
        createDomainMessage:
            'Athenz top level domain creation will be manual until it is integrated with an updated Yahoo product taxonomy. \n If your product does not have a top level domain already registered in Athenz, you can file a JIRA ticket in the JIRA ATHENS queue. \n Please provide the Product ID for your product from "Product Master", a short and descriptive domain name and list of administrators identified by their Okta Short IDs. \n',
        cspReportUri: 'https://csp.yahoo.com/beacon/csp?src=athenz',
        cspImgSrc: ['https://directory.ouryahoo.com'],
        formAction: [
            'https://signin.aws.amazon.com/saml',
            'https://console.aws.amazon.com/console/home',
        ],
        allPrefixes: [
            {
                name: 'AWS',
                prefix: ':role.aws',
            },
            {
                name: 'Calypso',
                prefix: ':role.ums',
            },
            {
                name: 'CKMS',
                prefix: ':role.paranoids.ppse.ckms.ykeykey_',
            },
            {
                name: 'Yamas',
                prefix: ':role.yamas.tenancy',
            },
            {
                name: 'Kubernetes',
                prefix: ':role.k8s',
            },
            {
                name: 'Sherpa',
                prefix: ':role.sherpa.tenancy',
            },
            {
                name: 'Microsegmentation',
                prefix: ':role.acl',
            },
            {
                name: 'Halo',
                prefix: ':role.halo',
            },
        ],
        featureFlag: true,
        pageFeatureFlag: {
            microsegmentation: {
                policyValidation: true,
            },
        },
        serviceHeaderLinks: [
            {
                description:
                    'Here you can add / see instances which can not obtain Athenz identity because of limitations, but would be associated with your service.',
                url: 'http://yo/service-instances',
                target: '_blank',
            },
            {
                description:
                    'Here you can see instances which are running with this service identity',
                url: 'http://yo/service-instances',
                target: '_blank',
            },
        ],
        templates: ['openhouse', 'owshome'],
        msdAuthHeaderPath:
            '/var/lib/sia/tokens/msd-api-access/msd-api-access-token',
        numberOfRetry: 2,
    },
};

// returns configuration customized for runtime environment
module.exports = function () {
    let env = process.env.APP_ENV ? process.env.APP_ENV : 'local';
    const c = config[env];
    c.env = env;
    // Expire cookies after half hour. Timeout to be mentioned in seconds
    c.oktaTimeout = 18000;
    return c;
};
