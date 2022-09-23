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
import React from 'react';
import { render } from '@testing-library/react';
import AddRuleFormForRole from '../../../components/role-policy/AddRuleFormForRole';

describe('AddRuleForm', () => {
    it('should render', () => {
        const api = {
            listRoles(domain) {
                return new Promise((resolve, reject) => {
                    resolve(['a, b']);
                });
            },
        };
        const { getByTestId } = render(<AddRuleFormForRole api={api} />);
        const addRuleFormForRole = getByTestId('add-rule-form-for-role');
        expect(addRuleFormForRole).toMatchSnapshot();
    });
    it('should render failed to load roles', () => {
        const api = {
            listRoles(domain) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 404,
                        body: { message: 'Got Error from Api' },
                    });
                });
            },
        };
        const { getByTestId } = render(<AddRuleFormForRole api={api} />);
        const addRuleFormForRole = getByTestId('add-rule-form-for-role');
        expect(addRuleFormForRole).toMatchSnapshot();
    });
});
