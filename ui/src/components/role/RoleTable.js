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
import RoleRow from './RoleRow';
import RoleGroup from './RoleGroup';

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

export default class RoleTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;

        let subRows = [];

        if (props.prefixes) {
            props.prefixes.map((prefix) => {
                let rows = props.roles.filter((item) =>
                    item.name.startsWith(props.domain + prefix.prefix)
                );
                subRows[prefix.name] = rows;
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
                this.props.prefixes.map((prefix) => {
                    let rows = this.props.roles.filter((item) =>
                        item.name.startsWith(this.props.domain + prefix.prefix)
                    );
                    subRows[prefix.name] = rows;
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
        const adminRole = domain + ':role.admin';
        let rows = [];

        if (this.state.roles && this.state.roles.length > 0) {
            let remainingRows = this.state.roles.filter((item) => {
                if (item.name === adminRole) {
                    return false;
                }
                let included = false;
                if (this.props.prefixes) {
                    this.props.prefixes.forEach((prefix) => {
                        if (
                            item.name.startsWith(
                                this.props.domain + prefix.prefix
                            )
                        ) {
                            included = true;
                        }
                    });
                }

                return !included;
            });

            // put admin role at first place
            let adminRow = this.state.roles
                .filter((item) => {
                    return item.name == adminRole;
                })
                .map((item, i) => {
                    return (
                        <RoleRow
                            details={item}
                            idx={i}
                            domain={domain}
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

            rows.push(adminRow);

            if (this.state.rows) {
                for (let name in this.state.rows) {
                    // group rows
                    let roleGroup = (
                        <RoleGroup
                            api={this.api}
                            domain={domain}
                            name={name}
                            roles={this.state.rows[name]}
                            onUpdateSuccess={this.props.onSubmit}
                            _csrf={this.props._csrf}
                        />
                    );

                    rows.push(roleGroup);
                }
            }

            let otherRows = remainingRows
                .sort((a, b) => {
                    return a.name.localeCompare(b.name);
                })
                .map((item, i) => {
                    return (
                        <RoleRow
                            details={item}
                            idx={i}
                            domain={domain}
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

            rows.push(otherRows);
        }

        return (
            <StyleTable key='role-table' data-testid='roletable'>
                <thead>
                    <tr>
                        <TableHeadStyledRoleName align={left}>
                            Role
                        </TableHeadStyledRoleName>
                        <TableHeadStyled align={left}>
                            Modified Date
                        </TableHeadStyled>
                        <TableHeadStyled align={left}>
                            Reviewed Date
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Members
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>Review</TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Policy Rule
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Settings
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>Delete</TableHeadStyled>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </StyleTable>
        );
    }
}
