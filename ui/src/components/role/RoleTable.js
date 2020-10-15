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
import {
    AWS_ROLE_PREFIX,
    UMS_ROLE_PREFIX,
    CKMS_ROLE_PREFIX,
} from '../constants/constants';

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

const LeftMarginSpan = styled.span`
    margin-right: 10px;
    verticalAlign：bottom；
`;

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const TrStyled = styled.tr`
    box-sizing: border-box;
    margin-top: 5px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    height: 50px;
`;

export default class RoleTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;

        let awsRows = props.roles.filter((item) =>
            item.name.startsWith(props.domain + AWS_ROLE_PREFIX)
        );
        let umsRows = props.roles.filter((item) =>
            item.name.startsWith(props.domain + UMS_ROLE_PREFIX)
        );
        let ckmsRows = props.roles.filter((item) =>
            item.name.startsWith(props.domain + CKMS_ROLE_PREFIX)
        );

        let subRows = [];
        subRows['aws'] = awsRows;
        subRows['ums'] = umsRows;
        subRows['ckms'] = ckmsRows;

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
            let awsRows = this.props.roles.filter((item) =>
                item.name.startsWith(this.props.domain + AWS_ROLE_PREFIX)
            );
            let umsRows = this.props.roles.filter((item) =>
                item.name.startsWith(this.props.domain + UMS_ROLE_PREFIX)
            );
            let ckmsRows = this.props.roles.filter((item) =>
                item.name.startsWith(this.props.domain + CKMS_ROLE_PREFIX)
            );

            let subRows = [];
            subRows['aws'] = awsRows;
            subRows['ums'] = umsRows;
            subRows['ckms'] = ckmsRows;

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
        const awsRolePrefix = domain + ':role.aws.';
        const umsRolePrefix = domain + ':role.ums.';
        const ckmsRolePrefix = domain + ':role.paranoids.ppse.ckms.ykeykey_';
        const adminRole = domain + ':role.admin';
        const awsRoleName = 'aws';
        const umsRoleName = 'ums';
        const ckmsRoleName = 'ckms';
        let rows = [];

        if (this.state.roles && this.state.roles.length > 0) {
            let remainingRows = this.state.roles.filter(
                (item) =>
                    !item.name.startsWith(awsRolePrefix) &&
                    !item.name.startsWith(umsRolePrefix) &&
                    !item.name.startsWith(ckmsRolePrefix) &&
                    item.name !== adminRole
            );

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

            // AWS rows
            let awsGroup = (
                <RoleGroup
                    api={this.api}
                    domain={domain}
                    name={awsRoleName}
                    roles={this.state.rows[awsRoleName]}
                    onUpdateSuccess={this.props.onSubmit}
                    _csrf={this.props._csrf}
                />
            );

            rows.push(awsGroup);

            // UMS rows
            let umsGroup = (
                <RoleGroup
                    api={this.api}
                    domain={domain}
                    name={umsRoleName}
                    roles={this.state.rows[umsRoleName]}
                    onUpdateSuccess={this.props.onSubmit}
                    _csrf={this.props._csrf}
                />
            );

            rows.push(umsGroup);

            // CKMS rows
            let ckmsGroup = (
                <RoleGroup
                    api={this.api}
                    domain={domain}
                    name={ckmsRoleName}
                    roles={this.state.rows[ckmsRoleName]}
                    onUpdateSuccess={this.props.onSubmit}
                    _csrf={this.props._csrf}
                />
            );

            rows.push(ckmsGroup);

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
