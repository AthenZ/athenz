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
import RoleGroup from '../role/RoleGroup';

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

export default class GroupRoleTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        let subRows = [];

        if (props.prefixes) {
            props.prefixes.forEach((prefix) => {
                let rows = props.roles.filter(
                    (item) => item.domainName == prefix
                );
                subRows[prefix] = rows;
            });
        }

        this.state = {
            roles: props.roles || [],
            rows: subRows,
        };
    }

    componentDidUpdate = (prevProps) => {
        if (prevProps.domain !== this.props.domain) {
            this.setState({
                rows: {},
            });
        } else if (prevProps.roles !== this.props.roles) {
            let subRows = [];
            if (this.props.prefixes) {
                this.props.prefixes.forEach((prefix) => {
                    let rows = this.props.roles.filter(
                        (item) => item.domainName == prefix
                    );
                    subRows[prefix] = rows;
                });
            }

            this.setState({
                roles: this.props.roles || [],
                rows: subRows,
            });
        }
    };

    render() {
        const center = 'center';
        const left = 'left';
        const { domain } = this.props;
        let rows = [];

        if (this.state.roles && this.state.roles.length > 0) {
            if (this.state.rows) {
                for (let name in this.state.rows) {
                    // group rows
                    let roleGroup = (
                        <RoleGroup
                            category={'group-roles'}
                            key={'group-role:' + name}
                            api={this.api}
                            domain={name}
                            name={name}
                            roles={this.state.rows[name]}
                            onUpdateSuccess={this.props.onSubmit}
                            _csrf={this.props._csrf}
                        />
                    );
                    rows.push(roleGroup);
                }
            }
        }

        return (
            <StyleTable key='role-table' data-testid='roletable'>
                <thead>
                    <tr>
                        <TableHeadStyledRoleName align={left}>
                            Role
                        </TableHeadStyledRoleName>
                        <TableHeadStyled align={center}>
                            Expiry Date
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Members
                        </TableHeadStyled>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </StyleTable>
        );
    }
}
