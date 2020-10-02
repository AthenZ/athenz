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
import ReviewRow from './ReviewRow';

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0 15px;
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

export default class ReviewTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
    }

    render() {
        const center = 'center';
        const left = 'left';
        const { domain, role } = this.props;
        let rows = [];

        if (this.props.members && this.props.members.length > 0) {
            rows = this.props.members
                .filter((item) => item.approved === false)
                .sort((a, b) => {
                    return a.name.localeCompare(b.memberName);
                })
                .map((item, i) => {
                    return (
                        <ReviewRow
                            domain={domain}
                            role={role}
                            details={item}
                            idx={i}
                            api={this.api}
                            key={item.memberName}
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
            <StyleTable data-testid='member-table'>
                <thead>
                    <tr>
                        <TableHeadStyledRoleName align={left}>
                            User Name
                        </TableHeadStyledRoleName>
                        <TableHeadStyled align={left}>
                            Name of User
                        </TableHeadStyled>
                        <TableHeadStyled align={left}>
                            Review By Date
                        </TableHeadStyled>
                        <TableHeadStyled align={left}>
                            Review Last Notified Date
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Approve
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>Deny</TableHeadStyled>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </StyleTable>
        );
    }
}
