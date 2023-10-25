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
import { modified } from '../../config/config.test';

describe('Service Config', () => {
    it('should get default config', () => {
        expect(singleStoreService).not.toBeNull();
    });
});

export const singleStoreService = {
    name: 'dom.singleService',
    description: 'for testing',
    modified: modified,
    publicKeys: {
        1: {
            id: '1',
            key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
        },
    },
};

export const singleApiService = {
    name: 'dom.singleService',
    description: 'for testing',
    publicKeys: [
        {
            key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
            id: '1',
        },
    ],
    modified: modified,
};

export const apiServices = [
    {
        name: 'dom.service1',
        publicKeys: [
            {
                key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                id: '1',
            },
            {
                key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBb1BqVm5UdXhkOGRwMC9ZTWh6TXIKOURpS0pUUXdrNWphdktKR2RHY29wQ2Ura1lWMHRFQnpGL1VCRWpjYVpuNnd4eGRjZU5wZkhuSVN6SG5abVNFKwpjRGUwY09yc3BPZ1c5d1VGdE9BcGpJZ2krUmxiOC93ck1iMmF1YXV2NUxoRW9ORm9ueCs3TVdSRnptUmZvaG91Cm9pd1h2czJ2V2x4Z0JXelo4UHVHSUlsTERNK3ltWlFxamlPbERjOWF2ZVpraXpUZFJBMG9veTFoRUZyK3ZNRWMKK2ZYY29aQ0F0S0J2aHNuKzFhb2ZPMU9pZ2ljYS9WaCtSSm1ieUNBem1tVFpia0I4emJUaE1vK1cxNmhXeUl0dQpJM1VoMlhHYTZ4dVhyQ0FBQ1FLVVR5TDdGRkl2OXhLUExtVWRXYkdYd3NTZ0FBazZjV2x3WTZJcW4zUHJQSmpTCmNRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--',
                id: '2',
            },
        ],
        modified: modified,
    },
    {
        name: 'dom.service2',
        publicKeys: [
            {
                key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                id: '1',
            },
        ],
        modified: modified,
    },
];

export const configStoreServices = {
    'dom.service1': {
        name: 'dom.service1',
        description: 'service for test',
        tags: {
            tag: { list: ['tag1', 'tag2'] },
            tag2: { list: ['tag3'] },
        },
        publicKeys: {
            1: {
                key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                id: '1',
            },
            2: {
                key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBb1BqVm5UdXhkOGRwMC9ZTWh6TXIKOURpS0pUUXdrNWphdktKR2RHY29wQ2Ura1lWMHRFQnpGL1VCRWpjYVpuNnd4eGRjZU5wZkhuSVN6SG5abVNFKwpjRGUwY09yc3BPZ1c5d1VGdE9BcGpJZ2krUmxiOC93ck1iMmF1YXV2NUxoRW9ORm9ueCs3TVdSRnptUmZvaG91Cm9pd1h2czJ2V2x4Z0JXelo4UHVHSUlsTERNK3ltWlFxamlPbERjOWF2ZVpraXpUZFJBMG9veTFoRUZyK3ZNRWMKK2ZYY29aQ0F0S0J2aHNuKzFhb2ZPMU9pZ2ljYS9WaCtSSm1ieUNBem1tVFpia0I4emJUaE1vK1cxNmhXeUl0dQpJM1VoMlhHYTZ4dVhyQ0FBQ1FLVVR5TDdGRkl2OXhLUExtVWRXYkdYd3NTZ0FBazZjV2x3WTZJcW4zUHJQSmpTCmNRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--',
                id: '2',
            },
        },
        modified: modified,
    },
    'dom.service2': {
        name: 'dom.service2',
        tags: {
            tag: { list: ['tag1', 'tag2'] },
        },
        publicKeys: {
            1: {
                key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                id: '1',
            },
        },
        modified: modified,
        provider: {
            aws_lambda_instance_launch_provider: 'allow',
            openstack_instance_launch_provider: 'not',
            secureboot_instance_launch_provider: 'not',
            aws_ecs_instance_launch_provider: 'allow',
            zts_instance_launch_provider: 'not',
            vespa_instance_launch_provider: 'not',
            ybiip_instance_launch_provider: 'not',
            azure_instance_launch_provider: 'not',
            k8s_omega_instance_launch_provider: 'not',
            aws_instance_launch_provider: 'allow',
        },
        serviceHeaderDetails: {
            static: {
                description:
                    'Here you can add / see instances which can not obtain Athenz identity because of limitations, but would be associated with your service.',
                url: 'http://yo/service-instances',
                target: '_blank',
            },
            dynamic: {
                description:
                    'Here you can see instances which are running with this service identity',
                url: 'http://yo/service-instances',
                target: '_blank',
            },
        },
        staticInstances: {
            workLoadData: [
                {
                    domainName: 'dom',
                    serviceName: 'ows',
                    type: 'EXTERNAL_APPLIANCE',
                    ipAddresses: ['100.100.100.2'],
                    name: '100.100.100.2',
                    updateTime: '2022-08-02T16:57:24.373Z',
                },
                {
                    domainName: 'dom',
                    serviceName: 'ows',
                    type: 'EXTERNAL_APPLIANCE',
                    ipAddresses: ['101.101.101.2'],
                    name: '101.101.101.2',
                    updateTime: '2022-08-03T11:07:02.416Z',
                },
                {
                    domainName: 'dom',
                    serviceName: 'ows',
                    type: 'SERVICE_SUBNET',
                    ipAddresses: ['101.101.101.2/20'],
                    name: '101.101.101.2/20',
                    updateTime: '2022-08-03T11:07:02.417Z',
                },
            ],
            workLoadMeta: {
                totalDynamic: 0,
                totalStatic: 3,
                totalRecords: 3,
                totalHealthyDynamic: 0,
            },
        },
        dynamicInstances: {
            workLoadData: [
                {
                    domainName: 'dom',
                    serviceName: 'ows',
                    uuid: '7982edfc-0b1b-4674-ad1c-55af492bd45d',
                    ipAddresses: [
                        '10.53.150.116',
                        '2001:4998:efeb:283:0:0:0:236',
                    ],
                    hostname: '7982edfc.dom.ne1.ows.oath.cloud',
                    provider: 'sys.openstack.provider-classic',
                    updateTime: '2022-08-01T18:00:40.240Z',
                    certExpiryTime: '2022-08-31T00:42:58.000Z',
                    certIssueTime: '2022-07-31T23:42:58.000Z',
                },
                {
                    domainName: 'dom',
                    serviceName: 'ows',
                    uuid: '11111111-1111-1111-1111-111111111111',
                    ipAddresses: [
                        '10.53.150.116',
                        '2001:4998:efeb:283:0:0:0:236',
                    ],
                    hostname: 'test.dom.ne1.ows.oath.cloud',
                    provider: 'sys.openstack.provider-classic',
                    updateTime: '2022-08-01T18:00:40.240Z',
                    certExpiryTime: '2022-08-31T00:42:58.000Z',
                    certIssueTime: '2022-07-31T23:42:58.000Z',
                },
            ],
            workLoadMeta: {
                totalDynamic: 2,
                totalStatic: 0,
                totalRecords: 2,
                totalHealthyDynamic: 2,
            },
        },
    },
};
