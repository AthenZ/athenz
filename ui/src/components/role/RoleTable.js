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
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import RoleRow from './RoleRow';

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;
const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    font-size: 0.8rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;

const TableHeadStyledRoleName = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    font-size: 0.8rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 35px;
    word-break: break-all;
`;

export default class RoleTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
    }

    render() {
        const center = 'center';
        const left = 'left';
        const { domain } = this.props;
        let rows = [];

        if (this.props.roles && this.props.roles.length > 0) {
            rows = this.props.roles
                .sort((a, b) => {
                    return a.name.localeCompare(b.name);
                })
                .map((item, i) => {
                    let color = '';
                    if (i % 2 === 0) {
                        color = colors.row;
                    }
                    return (
                        <RoleRow
                            details={item}
                            idx={i}
                            domain={domain}
                            color={color}
                            api={this.api}
                            key={item.name}
                            onUpdateSuccess={this.props.onSubmit}
                            _csrf={this.props._csrf}
                            justificationRequired={
                                this.props.justificationRequired
                            }
                            userProfileLink={this.props.userProfileLink}
                        />
                    );
                });
        }

        return (
            <StyleTable data-testid='roletable'>
                <thead>
                    <tr>
                        <TableHeadStyledRoleName align={left}>
                            Role
                        </TableHeadStyledRoleName>
                        <TableHeadStyled align={left}>
                            Modified Date
                        </TableHeadStyled>
                        <TableHeadStyled align={left}>
                            Last Reviewed Date
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Review Enabled
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Self Served
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Members
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>Review</TableHeadStyled>
                        <TableHeadStyled align={center}>Delete</TableHeadStyled>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </StyleTable>
        );
    }
}
