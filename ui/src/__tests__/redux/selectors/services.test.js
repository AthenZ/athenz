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
import { domainName, expiry, modified } from '../../config/config.test';
import { configStoreServices } from '../config/service.test';
import {
    selectAllProviders,
    selectDynamicServiceHeaderDetails,
    selectProvider,
    selectService,
    selectServiceDescription,
    selectServicePublicKeys,
    selectServices,
    selectServiceTags,
    thunkSelectServices,
    selectStaticServiceHeaderDetails,
    selectInstancesWorkLoadMeta,
    selectInstancesWorkLoadData,
} from '../../../redux/selectors/services';
import { _ } from 'lodash';

describe('test service selectors', () => {
    const stateWithServices = {
        services: {
            domainName,
            expiry,
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
            ],
            services: configStoreServices,
        },
    };
    const stateWithoutServices = {
        services: {
            domainName,
            expiry,
        },
    };
    describe('test thunkSelectServices selector', () => {
        it('should return services', () => {
            expect(thunkSelectServices(stateWithServices)).toEqual(
                configStoreServices
            );
        });
        it('should return empty list', () => {
            expect(thunkSelectServices(stateWithoutServices)).toEqual([]);
        });
    });
    describe('test selectServices selector', () => {
        it('should return services', () => {
            const expectedServicesList = [
                {
                    name: 'dom.service1',
                    description: 'service for test',
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
                {
                    name: 'dom.service2',
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
                        ],
                        workLoadMeta: {
                            totalDynamic: 0,
                            totalStatic: 2,
                            totalRecords: 2,
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
                        ],
                        workLoadMeta: {
                            totalDynamic: 1,
                            totalStatic: 0,
                            totalRecords: 1,
                            totalHealthyDynamic: 1,
                        },
                    },
                },
            ];
            expect(
                _.isEqual(
                    selectServices(stateWithServices),
                    expectedServicesList
                )
            );
        });
        it('should return empty list', () => {
            expect(selectServices(stateWithoutServices)).toEqual([]);
        });
    });
    describe('test selectService selector', () => {
        it('should return service', () => {
            const expectedService = {
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
            };
            expect(
                selectService(stateWithServices, domainName, 'service1')
            ).toEqual(expectedService);
        });
        it('should return empty object', () => {
            expect(
                selectService(stateWithoutServices, domainName, 'service1')
            ).toEqual({});
        });
    });
    describe('test selectServicePublicKeys selector', () => {
        it('should return public keys', () => {
            const expectedPublicKeys = [
                {
                    key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                    id: '1',
                },
                {
                    key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBb1BqVm5UdXhkOGRwMC9ZTWh6TXIKOURpS0pUUXdrNWphdktKR2RHY29wQ2Ura1lWMHRFQnpGL1VCRWpjYVpuNnd4eGRjZU5wZkhuSVN6SG5abVNFKwpjRGUwY09yc3BPZ1c5d1VGdE9BcGpJZ2krUmxiOC93ck1iMmF1YXV2NUxoRW9ORm9ueCs3TVdSRnptUmZvaG91Cm9pd1h2czJ2V2x4Z0JXelo4UHVHSUlsTERNK3ltWlFxamlPbERjOWF2ZVpraXpUZFJBMG9veTFoRUZyK3ZNRWMKK2ZYY29aQ0F0S0J2aHNuKzFhb2ZPMU9pZ2ljYS9WaCtSSm1ieUNBem1tVFpia0I4emJUaE1vK1cxNmhXeUl0dQpJM1VoMlhHYTZ4dVhyQ0FBQ1FLVVR5TDdGRkl2OXhLUExtVWRXYkdYd3NTZ0FBazZjV2x3WTZJcW4zUHJQSmpTCmNRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--',
                    id: '2',
                },
            ];
            expect(
                selectServicePublicKeys(
                    stateWithServices,
                    domainName,
                    'service1'
                )
            ).toEqual(expectedPublicKeys);
        });
        it('should return empty list', () => {
            expect(
                selectServicePublicKeys(
                    stateWithoutServices,
                    domainName,
                    'service1'
                )
            ).toEqual([]);
        });
    });
    describe('test selectServiceDescription selector', () => {
        it('should return service description', () => {
            const expectedDescription = 'service for test';
            expect(
                selectServiceDescription(
                    stateWithServices,
                    domainName,
                    'service1'
                )
            ).toEqual(expectedDescription);
        });
        it('should return null', () => {
            expect(
                selectServiceDescription(
                    stateWithoutServices,
                    domainName,
                    'service1'
                )
            ).toEqual(null);
        });
    });
    describe('test selectProvider selector', () => {
        it('should return service provider', () => {
            const expectedProvider = {
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
            };
            expect(
                selectProvider(stateWithServices, domainName, 'service2')
            ).toEqual(expectedProvider);
        });
        it('should return empty object', () => {
            expect(
                selectProvider(stateWithoutServices, domainName, 'service2')
            ).toEqual({});
        });
    });
    describe('test selectAllProviders selector', () => {
        it('should return group tags', () => {
            const expectedProviders = [
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
            ];
            expect(selectAllProviders(stateWithServices)).toEqual(
                expectedProviders
            );
        });
        it('should return empty list', () => {
            expect(selectAllProviders(stateWithoutServices)).toEqual([]);
        });
    });
    describe('test selectDynamicServiceHeaderDetails selector', () => {
        it('should return dynamic header details', () => {
            let expectedDynamicHeaderDetails = {
                description:
                    'Here you can see instances which are running with this service identity',
                url: 'http://yo/service-instances',
                target: '_blank',
            };
            expect(
                selectDynamicServiceHeaderDetails(
                    stateWithServices,
                    'dom',
                    'service2'
                )
            ).toEqual(expectedDynamicHeaderDetails);
        });
        it('should return empty object', () => {
            expect(
                selectDynamicServiceHeaderDetails(
                    stateWithoutServices,
                    'dom',
                    'service2'
                )
            ).toEqual({});
        });
    });

    describe('test selectStaticServiceHeaderDetails selector', () => {
        it('should return static header details', () => {
            let expectedStaticHeaderDetails = {
                description:
                    'Here you can add / see instances which can not obtain Athenz identity because of limitations, but would be associated with your service.',
                url: 'http://yo/service-instances',
                target: '_blank',
            };
            expect(
                selectStaticServiceHeaderDetails(
                    stateWithServices,
                    'dom',
                    'service2'
                )
            ).toEqual(expectedStaticHeaderDetails);
        });
        it('should return empty object', () => {
            expect(
                selectStaticServiceHeaderDetails(
                    stateWithoutServices,
                    'dom',
                    'service2'
                )
            ).toEqual({});
        });
    });
    describe('test selectInstancesWorkLoadMeta selector', () => {
        it('should return dynamic work load meta', () => {
            let workLoadMeta = {
                totalDynamic: 2,
                totalStatic: 0,
                totalRecords: 2,
                totalHealthyDynamic: 2,
            };
            expect(
                selectInstancesWorkLoadMeta(
                    stateWithServices,
                    'dom',
                    'service2',
                    'dynamic'
                )
            ).toEqual(workLoadMeta);
        });
        it('should return empty object', () => {
            expect(
                selectInstancesWorkLoadMeta(
                    stateWithoutServices,
                    'dom',
                    'service2',
                    'dynamic'
                )
            ).toEqual({});
        });
        it('should return static work load meta', () => {
            let workLoadMeta = {
                totalDynamic: 0,
                totalStatic: 3,
                totalRecords: 3,
                totalHealthyDynamic: 0,
            };
            expect(
                selectInstancesWorkLoadMeta(
                    stateWithServices,
                    'dom',
                    'service2',
                    'static'
                )
            ).toEqual(workLoadMeta);
        });
        it('should return empty object', () => {
            expect(
                selectInstancesWorkLoadMeta(
                    stateWithoutServices,
                    'dom',
                    'service2',
                    'static'
                )
            ).toEqual({});
        });
    });
    describe('test selectInstancesWorkLoadData selector', () => {
        it('should return dynamic work load data', () => {
            let workLoadData = [
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
            ];
            expect(
                selectInstancesWorkLoadData(
                    stateWithServices,
                    'dom',
                    'service2',
                    'dynamic'
                )
            ).toEqual(workLoadData);
        });
        it('should return empty array', () => {
            expect(
                selectInstancesWorkLoadData(
                    stateWithoutServices,
                    'dom',
                    'service2',
                    'dynamic'
                )
            ).toEqual([]);
        });
        it('should return static work load data', () => {
            let workLoadData = [
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
            ];
            expect(
                selectInstancesWorkLoadData(
                    stateWithServices,
                    'dom',
                    'service2',
                    'static'
                )
            ).toEqual(workLoadData);
        });
        it('should return empty array', () => {
            expect(
                selectInstancesWorkLoadData(
                    stateWithoutServices,
                    'dom',
                    'service2',
                    'static'
                )
            ).toEqual([]);
        });
    });
    describe('test selectServiceTags selector', () => {
        it('should return service with tags', () => {
            const expectedRoleTags = {
                tag: { list: ['tag1', 'tag2'] },
                tag2: { list: ['tag3'] },
            };
            expect(
                selectServiceTags(stateWithServices, domainName, 'service1')
            ).toEqual(expectedRoleTags);
        });
        it('should return empty object', () => {
            expect(
                selectServiceTags(stateWithServices, domainName, 'admin')
            ).toEqual({});
        });
    });
});
