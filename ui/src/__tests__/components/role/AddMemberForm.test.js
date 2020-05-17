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
import AddMemberForm from "../../../components/role/AddMemberForm";
import API from "../../../api";

describe('AddMemberForm', () => {
    it('should render', () => {
        let domain = 'domain';
        let roleName ='roleName';
        let role = {
            roleMembers: [{ memberName: 'user.test1' }, { memberName: 'user.test2' }],
            memberExpiryDays: 30,
            serviceExpiryDays: 20,
            memberReviewDays: 70,
            serviceReviewDays:80
        };

        const { getByTestId } = render(
            <AddMemberForm
                api={API()}
                domain={domain}
                role={roleName}
                roleObj={role}
                justificationRequired={true}
            />
        );
        const roleMemberForm = getByTestId('add-member-form');
        expect(roleMemberForm).toMatchSnapshot();
    });
});
