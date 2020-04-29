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
import React from 'react';
import { render, fireEvent } from '@testing-library/react';
import CreateDomain from '../../../components/domain/CreateDomain';
import API from '../../../api';

describe('CreateDomains', () => {
    it('should render', () => {
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        let createDomainMessage =
            'Athenz top level domain creation is manual. \n Please connect with your system administrator to create top level domains. \n';
        let api = {};
        const { getByTestId } = render(
            <CreateDomain
                domains={domains}
                api={api}
                createDomainMessage={createDomainMessage}
            />
        );
        const userDomains = getByTestId('buttongroup');
        expect(userDomains).toMatchSnapshot();
    });
});
