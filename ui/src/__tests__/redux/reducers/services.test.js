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
import { _ } from 'lodash';
import {
    configStoreServices,
    singleStoreService,
} from '../config/service.test';
import { domainName, expiry, modified } from '../../config/config.test';
import { services } from '../../../redux/reducers/services';
import {
    ADD_KEY_TO_STORE,
    ADD_SERVICE_HOST_TO_STORE,
    ADD_SERVICE_TO_STORE,
    ALLOW_PROVIDER_TEMPLATE_TO_STORE,
    DELETE_KEY_FROM_STORE,
    DELETE_SERVICE_FROM_STORE,
    DELETE_SERVICE_INSTANCE_FROM_STORE,
    LOAD_INSTANCES_TO_STORE,
    LOAD_PROVIDER_TO_STORE,
    LOAD_SERVICE_HEADER_DETAILS_TO_STORE,
    LOAD_SERVICES,
} from '../../../redux/actions/services';
import AppUtils from '../../../components/utils/AppUtils';

describe('Services Reducer', () => {
    it('should load the services in', () => {
        const initialState = {};
        const action = {
            type: LOAD_SERVICES,
            payload: {
                services: configStoreServices,
                domainName: domainName,
                expiry: expiry,
            },
        };
        const expectedState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const newState = services(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add a service in', () => {
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ADD_SERVICE_TO_STORE,
            payload: {
                serviceData: singleStoreService,
                serviceFullName: 'dom.singleService',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.services['dom.singleService'] = {
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
        const newState = services(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should delete service', () => {
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_SERVICE_FROM_STORE,
            payload: {
                serviceFullName: 'dom.service1',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.services['dom.service1'];
        const newState = services(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete dynamic instance', () => {
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_SERVICE_INSTANCE_FROM_STORE,
            payload: {
                serviceFullName: 'dom.service2',
                category: 'dynamic',
                instanceId: '11111111-1111-1111-1111-111111111111',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.services['dom.service2'].dynamicInstances.workLoadData =
            expectedState.services[
                'dom.service2'
            ].dynamicInstances.workLoadData.filter((instance) => {
                return instance.uuid != '11111111-1111-1111-1111-111111111111';
            });
        expectedState.services['dom.service2'].dynamicInstances.workLoadMeta
            .totalDynamic--;
        expectedState.services['dom.service2'].dynamicInstances.workLoadMeta
            .totalHealthyDynamic--;
        expectedState.services['dom.service2'].dynamicInstances.workLoadMeta
            .totalRecords--;
        const newState = services(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
        expect(
            _.isEqual(
                Object.keys(
                    expectedState.services['dom.service2'].dynamicInstances
                        .workLoadData
                ).length,
                1
            )
        ).toBeTruthy();
    });
    it('should delete static instance', () => {
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_SERVICE_INSTANCE_FROM_STORE,
            payload: {
                serviceFullName: 'dom.service2',
                category: 'static',
                instanceId: '100.100.100.2',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.services['dom.service2'].staticInstances.workLoadData =
            expectedState.services[
                'dom.service2'
            ].staticInstances.workLoadData.filter((instance) => {
                return instance.name !== '100.100.100.2';
            });
        expectedState.services['dom.service2'].staticInstances.workLoadMeta
            .totalStatic--;
        expectedState.services['dom.service2'].staticInstances.workLoadMeta
            .totalRecords--;
        const newState = services(initialState, action);
        expect(newState).toEqual(expectedState);
        expect(
            _.isEqual(
                Object.keys(
                    expectedState.services['dom.service2'].staticInstances
                        .workLoadData
                ).length,
                2
            )
        ).toBeTruthy();
    });
    it('should delete static instance should work even when instanceId includes a /', () => {
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_SERVICE_INSTANCE_FROM_STORE,
            payload: {
                serviceFullName: 'dom.service2',
                category: 'static',
                instanceId: '101.101.101.2/20',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.services['dom.service2'].staticInstances.workLoadData =
            expectedState.services[
                'dom.service2'
            ].staticInstances.workLoadData.filter((instance) => {
                return instance.name !== '101.101.101.2/20';
            });
        expectedState.services['dom.service2'].staticInstances.workLoadMeta
            .totalStatic--;
        expectedState.services['dom.service2'].staticInstances.workLoadMeta
            .totalRecords--;
        const newState = services(initialState, action);
        expect(newState).toEqual(expectedState);
        expect(
            _.isEqual(
                Object.keys(
                    expectedState.services['dom.service2'].staticInstances
                        .workLoadData
                ).length,
                2
            )
        ).toBeTruthy();
    });
    it('should add key to service1', () => {
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ADD_KEY_TO_STORE,
            payload: {
                serviceFullName: 'dom.service1',
                keyId: '3',
                keyValue:
                    'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.services['dom.service1'].publicKeys['3'] = {
            key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
            id: '3',
        };
        const newState = services(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete key from service1', () => {
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_KEY_FROM_STORE,
            payload: {
                serviceFullName: 'dom.service1',
                keyId: '1',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.services['dom.service1'].publicKeys['1'];
        const newState = services(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should load providers to service1 and all providers to services', () => {
        let provider = {
            aws_lambda_instance_launch_provider: 'allow',
            openstack_instance_launch_provider: 'allow',
            secureboot_instance_launch_provider: 'not',
            aws_ecs_instance_launch_provider: 'allow',
            zts_instance_launch_provider: 'allow',
            vespa_instance_launch_provider: 'allow',
            ybiip_instance_launch_provider: 'not',
            azure_instance_launch_provider: 'not',
            k8s_omega_instance_launch_provider: 'allow',
            aws_instance_launch_provider: 'allow',
        };
        let allProviders = [
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
        ];
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: LOAD_PROVIDER_TO_STORE,
            payload: {
                serviceFullName: 'dom.service1',
                provider: provider,
                allProviders: allProviders,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.services['dom.service1'].provider = provider;
        expectedState.allProviders = allProviders;
        const newState = services(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should load providers to service1 and not load all providers to services', () => {
        let provider = {
            aws_lambda_instance_launch_provider: 'allow',
            openstack_instance_launch_provider: 'allow',
            secureboot_instance_launch_provider: 'not',
            aws_ecs_instance_launch_provider: 'allow',
            zts_instance_launch_provider: 'allow',
            vespa_instance_launch_provider: 'allow',
            ybiip_instance_launch_provider: 'not',
            azure_instance_launch_provider: 'not',
            k8s_omega_instance_launch_provider: 'allow',
            aws_instance_launch_provider: 'allow',
        };
        let allProviders = [
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
        ];
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
            allProviders: [],
        };
        const action = {
            type: LOAD_PROVIDER_TO_STORE,
            payload: {
                serviceFullName: 'dom.service1',
                provider: provider,
                allProviders: allProviders,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.services['dom.service1'].provider = provider;
        expectedState.allProviders = [];
        const newState = services(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should allow provider openstack_instance_launch_provider to service2', () => {
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ALLOW_PROVIDER_TEMPLATE_TO_STORE,
            payload: {
                serviceFullName: 'dom.service2',
                providerId: 'openstack_instance_launch_provider',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expect(
            expectedState.services['dom.service2'].provider[
                'openstack_instance_launch_provider'
            ] === 'not'
        );
        expectedState.services['dom.service2'].provider[
            'openstack_instance_launch_provider'
        ] = 'allow';
        const newState = services(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should load dynamic instance into service2', () => {
        let dynamicInstance = {
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
        };
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: LOAD_INSTANCES_TO_STORE,
            payload: {
                serviceFullName: 'dom.service2',
                category: 'dynamic',
                instances: dynamicInstance,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.services['dom.service2'].dynamicInstances =
            dynamicInstance;
        const newState = services(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should load static instance into service1', () => {
        let staticInstance = {
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
        };
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: LOAD_INSTANCES_TO_STORE,
            payload: {
                serviceFullName: 'dom.service1',
                category: 'static',
                instances: staticInstance,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.services['dom.service1'].staticInstances = staticInstance;
        const newState = services(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should load instance header into service2', () => {
        let serviceHeaderDetails = {
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
        };
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: LOAD_SERVICE_HEADER_DETAILS_TO_STORE,
            payload: {
                serviceFullName: 'dom.service2',
                serviceHeaderDetails,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.services['dom.service2'].serviceHeaderDetails =
            serviceHeaderDetails;
        const newState = services(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add a host into service2 static instances', () => {
        let host = {
            domainName: 'dom',
            ipAddresses: ['111.111.111.1'],
            name: '111.111.111.1',
            serviceName: 'ows',
            type: 'EXTERNAL_APPLIANCE',
            updateTime: '2022-08-03T15:11:04.544Z',
        };
        const initialState = {
            services: configStoreServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ADD_SERVICE_HOST_TO_STORE,
            payload: {
                serviceFullName: 'dom.service2',
                host,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.services['dom.service2'].staticInstances = {
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
                {
                    domainName: 'dom',
                    ipAddresses: ['111.111.111.1'],
                    name: '111.111.111.1',
                    serviceName: 'ows',
                    type: 'EXTERNAL_APPLIANCE',
                    updateTime: '2022-08-03T15:11:04.544Z',
                },
            ],
            workLoadMeta: {
                totalDynamic: 0,
                totalStatic: 4,
                totalRecords: 4,
                totalHealthyDynamic: 0,
            },
        };
        const newState = services(initialState, action);
        expect(newState).toEqual(expectedState);
    });
});
