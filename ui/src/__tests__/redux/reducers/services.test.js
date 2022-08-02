import { LOAD_ROLES } from '../../../redux/actions/roles';
import { _ } from 'lodash';
import {
    domainName,
    expiry,
    singleStoreService,
    storeServices,
} from '../../config/config.test';
import { services } from '../../../redux/reducers/services';
import {
    ADD_KEY_TO_STORE,
    ADD_SERVICE_TO_STORE,
    ALLOW_PROVIDER_TEMPLATE_TO_STORE,
    DELETE_KEY_FROM_STORE,
    DELETE_SERVICE_FROM_STORE,
    LOAD_PROVIDER_TO_STORE,
    LOAD_SERVICES,
} from '../../../redux/actions/services';
import AppUtils from '../../../components/utils/AppUtils';

describe('Services Reducer', () => {
    it('should load the services in', () => {
        const initialState = {};
        const action = {
            type: LOAD_SERVICES,
            payload: {
                services: storeServices,
                domainName: domainName,
                expiry: expiry,
            },
        };
        const expectedState = {
            services: storeServices,
            domainName: domainName,
            expiry: expiry,
        };
        const newState = services(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add a service in', () => {
        const initialState = {
            services: storeServices,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ADD_SERVICE_TO_STORE,
            payload: {
                serviceData: singleStoreService,
                serviceFullName: 'dom:singleService',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.services['dom:singleService'] = {
            name: 'dom:singleService',
            publicKeys: {
                1: {
                    id: '1',
                    key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                },
            },
        };
        const newState = services(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete service', () => {
        const initialState = {
            services: storeServices,
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
    it('should add key to service1', () => {
        const initialState = {
            services: storeServices,
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
            services: storeServices,
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
            services: storeServices,
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
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
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
            services: storeServices,
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
            services: storeServices,
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
});
