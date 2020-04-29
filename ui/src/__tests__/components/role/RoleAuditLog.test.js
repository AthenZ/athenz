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
import { render } from '@testing-library/react';
import RoleAuditLog from '../../../components/role/RoleAuditLog';
import { colors } from '../../../components/denali/styles';

describe('RoleAuditLog', () => {
    it('should render', () => {
        let auditLogRows = [
            {
                member: 'home.pgote.*',
                admin: 'user.pgote',
                created: '2020-02-17T22:29:16.000Z',
                action: 'ADD',
                auditRef: 'test',
            },
        ];
        let color = colors.white;

        const { getByTestId } = render(
            <RoleAuditLog auditLogRows={auditLogRows} color={color} />
        );
        const auditLogList = getByTestId('audit-log-list');

        expect(auditLogList).toMatchSnapshot();
    });
});
