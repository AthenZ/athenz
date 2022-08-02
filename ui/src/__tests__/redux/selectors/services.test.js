import {
    domainName,
    expiry,
    modified,
    storeServices,
} from '../../config/config.test';
import {
    selectAllProviders,
    selectProvider,
    selectService,
    selectServiceDescription,
    selectServicePublicKeys,
    selectServices,
    thunkSelectServices,
} from '../../../redux/selectors/services';

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
            services: storeServices,
        },
    };
    const stateWithoutServices = {
        services: {
            domainName,
            expiry,
        },
    };
    describe('test thunkSelectServices selector', () => {
        it('should return groups', () => {
            expect(thunkSelectServices(stateWithServices)).toEqual(
                storeServices
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
                },
            ];
            expect(selectServices(stateWithServices)).toEqual(
                expectedServicesList
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
});
