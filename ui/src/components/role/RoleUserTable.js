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
import styled from '@emotion/styled';

const StyleTableSub = styled.table`
    width: 100%;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

export default class RoleUserTable extends React.Component {
    constructor(props) {
        super(props);
    }
    render() {
        return (
            <td colSpan={3} data-testid='roleusertable'>
                <StyleTableSub>{this.props.children}</StyleTableSub>
            </td>
        );
    }
}
