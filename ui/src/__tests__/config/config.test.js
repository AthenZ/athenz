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

const config = require('../../config/config')();
describe('Config', () => {
    it('should get default config', () => {
        expect(config).not.toBeNull();
        expect(config.envLabel).toMatch(/unittest/);
    });
});

export const domainName = 'dom';
export const expiry = '2022-07-18T14:37:49.671Z';
export const modified = '2022-10-02T14:37:49.573Z';

export const apiServiceDependenciesData = [
    { service: 'dom1.service1', domain: 'dom' },
    {
        service: 'paranoids.service1',
        domain: 'dom',
        resourceGroups: [
            'resourcegroup.tenant.dom.res_group.test_2.workers',
            'resourcegroup.tenant.dom.res_group.test_res_grp1.readers',
            'resourcegroup.tenant.dom.res_group.test_res_grp1.writers',
        ],
    },
];

export const apiAssertionConditions = {
    conditionsList: [
        {
            id: 1,
            conditionsMap: {
                instance: {
                    operator: 'EQUAL',
                    value: 'test.com',
                },
                id: {
                    operator: 'EQUAL',
                    value: '1',
                },
                enforcementstate: {
                    operator: 'EQUAL',
                    value: 'report',
                },
            },
        },
    ],
};

export const storeInboundOutboundList = {
    inbound: [
        {
            layer: 'TCP',
            source_port: '1024-65535',
            destination_port: '4443-4443',
            conditionsList: [
                {
                    instances: 'test.com',
                    id: 1,
                    enforcementstate: 'report',
                    assertionId: 17389,
                    policyName: 'dom:policy.acl.openhouse.inbound',
                },
            ],
            destination_service: 'openhouse',
            source_services: ['yamas.api'],
            assertionIdx: 17389,
            identifier: 'test',
        },
        {
            layer: 'TCP',
            source_port: '1024-65535',
            destination_port: '4443-4443',
            conditionsList: [
                {
                    instances: 'test.com',
                    id: 1,
                    enforcementstate: 'report',
                    assertionId: 17417,
                    policyName: 'dom:policy.acl.ows.inbound',
                },
            ],
            destination_service: 'ows',
            source_services: ['yamas.api'],
            assertionIdx: 17417,
            identifier: 'test',
        },
    ],
    outbound: [
        {
            layer: 'TCP',
            source_port: '1024-65535',
            destination_port: '1024-65535',
            conditionsList: [
                {
                    instances: 'test.com',
                    id: 1,
                    enforcementstate: 'report',
                    assertionId: 17418,
                    policyName: 'dom:policy.acl.openhouse.outbound',
                },
            ],
            source_service: 'openhouse',
            destination_services: ['yamas.api'],
            assertionIdx: 17418,
            identifier: 'test',
        },
    ],
};

export const apiBusinessServicesAll = {
    validValues: [
        '0031636013124f40c0eebb722244b043:Search > Hot Search > Atomics > Database',
        '0031636013124f40c0eebb722244b044:IIOps > Name Space Management > Namer',
        '0031636013124f40c0eebb722244b045:CERT: Netflow',
    ],
};
export const storeBusinessServicesAll = [
    {
        value: '0031636013124f40c0eebb722244b043',
        name: 'Search > Hot Search > Atomics > Database',
    },
    {
        value: '0031636013124f40c0eebb722244b044',
        name: 'IIOps > Name Space Management > Namer',
    },
    {
        value: '0031636013124f40c0eebb722244b045',
        name: 'CERT: Netflow',
    },
];

export const allDomainList = [
    { name: 'abuse-pe', value: 'abuse-pe' },
    { name: 'act-adspec', value: 'act-adspec' },
    { name: 'ad-op-tools', value: 'ad-op-tools' },
    { name: 'ad-op-tools.ypm', value: 'ad-op-tools.ypm' },
    { name: 'ad-pe', value: 'ad-pe' },
    { name: 'ads-business-pe', value: 'ads-business-pe' },
    { name: 'adv-ds', value: 'adv-ds' },
    { name: 'adv-ds.blitz', value: 'adv-ds.blitz' },
    { name: 'adv-ds.core', value: 'adv-ds.core' },
    { name: 'adv-ds.core.hc-bot', value: 'adv-ds.core.hc-bot' },
    { name: 'adv-ds.kite', value: 'adv-ds.kite' },
    { name: 'adv-ds.lyrebird', value: 'adv-ds.lyrebird' },
    { name: 'adv-ds.puffin', value: 'adv-ds.puffin' },
    { name: 'adv-ds.puffin.gh-bot', value: 'adv-ds.puffin.gh-bot' },
    { name: 'advertising-pipelines', value: 'advertising-pipelines' },
    { name: 'advserving-pbp', value: 'advserving-pbp' },
    { name: 'adw', value: 'adw' },
    { name: 'adw.webservice', value: 'adw.webservice' },
    { name: 'aml', value: 'aml' },
    { name: 'aml.atlasdsx', value: 'aml.atlasdsx' },
    { name: 'analytics', value: 'analytics' },
    { name: 'analytics.maw', value: 'analytics.maw' },
    { name: 'angler', value: 'angler' },
    { name: 'answers', value: 'answers' },
    { name: 'argo', value: 'argo' },
    { name: 'artifactory', value: 'artifactory' },
    { name: 'athens', value: 'athens' },
    { name: 'athens.a1', value: 'athens.a1' },
    { name: 'athens.aws', value: 'athens.aws' },
    { name: 'athens.aws-ecs', value: 'athens.aws-ecs' },
    { name: 'athens.aws-lambda', value: 'athens.aws-lambda' },
    { name: 'athens.b1', value: 'athens.b1' },
    { name: 'athens.calypsodemo', value: 'athens.calypsodemo' },
    { name: 'athens.ci', value: 'athens.ci' },
    { name: 'athens.ci.test1', value: 'athens.ci.test1' },
    { name: 'athens.console', value: 'athens.console' },
    { name: 'athens.examples', value: 'athens.examples' },
    { name: 'athens.filter', value: 'athens.filter' },
    { name: 'athens.k8s', value: 'athens.k8s' },
    { name: 'athens.newkey', value: 'athens.newkey' },
    { name: 'athens.newkey2', value: 'athens.newkey2' },
    { name: 'athens.newkey3', value: 'athens.newkey3' },
    { name: 'athens.provider', value: 'athens.provider' },
    { name: 'athens.test', value: 'athens.test' },
    { name: 'athens.test1', value: 'athens.test1' },
    { name: 'athens.test2', value: 'athens.test2' },
    { name: 'athens.testci', value: 'athens.testci' },
    { name: 'athens.ui', value: 'athens.ui' },
    { name: 'athens.ui.asdfasdf', value: 'athens.ui.asdfasdf' },
    { name: 'athens.ui.test', value: 'athens.ui.test' },
    { name: 'athens.ui.zebra', value: 'athens.ui.zebra' },
    { name: 'athens.zpu', value: 'athens.zpu' },
    { name: 'athenz', value: 'athenz' },
    { name: 'athenz.dev', value: 'athenz.dev' },
    { name: 'athenz.oauth2', value: 'athenz.oauth2' },
    { name: 'athenz.stage', value: 'athenz.stage' },
    { name: 'athenz_provider_test', value: 'athenz_provider_test' },
    { name: 'atlas', value: 'atlas' },
    { name: 'auctions-hk', value: 'auctions-hk' },
    { name: 'auctions-tw-desktop', value: 'auctions-tw-desktop' },
    { name: 'aud-gca', value: 'aud-gca' },
    { name: 'audience-ds', value: 'audience-ds' },
    { name: 'avdom1', value: 'avdom1' },
    { name: 'avtest', value: 'avtest' },
    { name: 'avtest.child1', value: 'avtest.child1' },
    { name: 'avtest.child2', value: 'avtest.child2' },
    { name: 'avtest1', value: 'avtest1' },
    { name: 'avtest1.subdom1', value: 'avtest1.subdom1' },
    { name: 'avtest1.subdom2', value: 'avtest1.subdom2' },
    { name: 'bastion', value: 'bastion' },
    { name: 'bastion.cli', value: 'bastion.cli' },
    { name: 'billing-hk', value: 'billing-hk' },
    { name: 'billing-tw', value: 'billing-tw' },
    { name: 'blueprint', value: 'blueprint' },
    { name: 'bouncer', value: 'bouncer' },
    { name: 'brightroll-dsp-pe', value: 'brightroll-dsp-pe' },
    { name: 'broadway', value: 'broadway' },
    { name: 'brooklyn', value: 'brooklyn' },
    { name: 'brooklyn.config-push', value: 'brooklyn.config-push' },
    { name: 'calendar', value: 'calendar' },
    { name: 'calypso', value: 'calypso' },
    { name: 'calypso.demo', value: 'calypso.demo' },
    { name: 'calypso.fleet', value: 'calypso.fleet' },
    { name: 'cd', value: 'cd' },
    { name: 'cd.artifactory', value: 'cd.artifactory' },
    { name: 'cd.chef', value: 'cd.chef' },
    { name: 'cd.chef.cd', value: 'cd.chef.cd' },
    { name: 'cd.chef.oni', value: 'cd.chef.oni' },
    { name: 'cd.chef.ubiquity', value: 'cd.chef.ubiquity' },
    { name: 'cd.docker', value: 'cd.docker' },
    { name: 'cd.dropship', value: 'cd.dropship' },
    { name: 'cd.dropship.test', value: 'cd.dropship.test' },
    { name: 'cd.factory', value: 'cd.factory' },
    { name: 'cd.igor', value: 'cd.igor' },
    { name: 'cd.nodereg', value: 'cd.nodereg' },
    { name: 'cd.oni', value: 'cd.oni' },
    { name: 'cd.pogo', value: 'cd.pogo' },
    { name: 'cd.rolesdb', value: 'cd.rolesdb' },
    { name: 'cd.sauce-labs', value: 'cd.sauce-labs' },
    { name: 'cd.screwdriver', value: 'cd.screwdriver' },
    { name: 'cd.screwdriver.project', value: 'cd.screwdriver.project' },
    { name: 'cd.screwdriver.testapps', value: 'cd.screwdriver.testapps' },
    { name: 'cdsystest', value: 'cdsystest' },
    { name: 'cdsystest.screwdriver', value: 'cdsystest.screwdriver' },
];

export const userDomainList = [
    { name: 'avtest', adminDomain: true },
    { name: 'home.abhijetv', adminDomain: true },
    { name: 'home.olevi.test3', adminDomain: true },
    { name: 'home.relbaum', adminDomain: true },
    { name: 'home.relbaum.demo', adminDomain: true },
    { name: 'home.relbaum.redux-pr', adminDomain: true },
    { name: 'sys.auth', adminDomain: true },
    { name: 'sys.auth.redux', userDomain: true },
    { name: 'terraform-provider', adminDomain: true },
];
