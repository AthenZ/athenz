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
import RoleRow from './RoleRow';
//import 'denali-css/css/denali.css';
import RoleGroup from './RoleGroup';

const StyleTable = styled.div`
    width: 100%;
    border-spacing: 0 15px;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

const TableHeadStyled = styled.div`
    border-bottom: 2px solid rgb(213, 213, 213);
    color: rgb(154, 154, 154);
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0px 5px 15px;
    word-break: break-all;
    display: flex;
`;

const StyledNameCol = styled.div`
    text-align: ${(props) => props.align};
    width: 28%;
`;

const StyledTimeCol = styled.div`
    text-align: ${(props) => props.align};
    width: 15%;
`;

const StyledIconCol = styled.div`
    text-align: ${(props) => props.align};
    width: 7%;
`;

const TableHeadStyledRoleName = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 35px;
    word-break: break-all;
`;

export default class RoleTable extends React.Component {
    constructor(props) {
        super(props);
        let subRows = props.roles;
        if (props.prefixes) {
            props.prefixes.map((prefix) => {
                let rows = props.roles.filter((item) =>
                    item.name.startsWith(props.domain + prefix.prefix)
                );
                subRows[prefix.name] = rows;
            });
        }
        this.state = {
            rows: subRows,
        };
    }

    componentDidUpdate = (prevProps) => {
        if (prevProps.roles !== this.props.roles) {
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
        if (this.props.roles && this.props.roles.length > 0) {
            let remainingRows = this.props.roles.filter((item) => {
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
            let adminRow = this.props.roles
                .filter((item) => {
                    return item.name == adminRole;
                })
                .map((item, i) => {
                    return (
                        <RoleRow
                            details={item}
                            idx={i}
                            domain={domain}
                            key={item.name}
                            onUpdateSuccess={this.props.onSubmit}
                            timeZone={this.props.timeZone}
                            _csrf={this.props._csrf}
                        />
                    );
                });

            rows.push(adminRow);

            if (this.state.rows) {
                for (let name in this.state.rows) {
                    let roleGroup = (
                        <RoleGroup
                            key={'group:' + name}
                            domain={domain}
                            name={name}
                            roles={this.state.rows[name]}
                            onUpdateSuccess={this.props.onSubmit}
                            timeZone={this.props.timeZone}
                            _csrf={this.props._csrf}
                            newRole={this.props.newRole}
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
                            key={item.name}
                            onUpdateSuccess={this.props.onSubmit}
                            timeZone={this.props.timeZone}
                            _csrf={this.props._csrf}
                            newRole={this.props.newRole}
                        />
                    );
                });

            rows.push(otherRows);
        }

        return (
            <StyleTable key='role-table' data-testid='roletable'>
                <TableHeadStyled>
                    <StyledNameCol align={left}>Role</StyledNameCol>
                    <StyledTimeCol align={left}>Modified Date</StyledTimeCol>
                    <StyledTimeCol align={left}>Reviewed Date</StyledTimeCol>
                    <StyledIconCol align={center}>Members</StyledIconCol>
                    <StyledIconCol align={center}>Review</StyledIconCol>
                    <StyledIconCol align={center}>Policy Rule</StyledIconCol>
                    <StyledIconCol align={center}>Tags</StyledIconCol>
                    <StyledIconCol align={center}>Settings</StyledIconCol>
                    <StyledIconCol align={center}>History</StyledIconCol>
                    <StyledIconCol align={center}>Delete</StyledIconCol>
                </TableHeadStyled>
                {rows}
            </StyleTable>
        );
    }
}
