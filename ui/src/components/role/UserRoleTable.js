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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import RoleUserTable from './RoleUserTable';
import DeleteModal from '../modal/DeleteModal';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';

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

const TableHeadStyledUser = styled.th`
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
    width: 120px;
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

const TDStyledSub = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    width: 120px;
`;

export default class UserRoleTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.deleteRoleCancel = this.deleteRoleCancel.bind(this);
        this.saveJustification = this.saveJustification.bind(this);
        this.loadRoleByUser();
        this.state = {
            list: {},
            loaded: 'todo',
            expand: {},
            contents: {},
            showDelete: false,
            expandTable: {},
            showSuccess: false,
        };
        this.dateUtils = new DateUtils();
    }
    deleteItem(name, memberName) {
        this.setState({
            showDelete: true,
            deleteName: name,
            deleteMemberName: memberName,
            deleteMember: false,
        });
    }

    deleteItemMember(name) {
        this.setState({
            showDelete: true,
            deleteName: name,
            deleteMember: true,
        });
    }

    onSubmitDeleteMember(domain) {
        if (
            this.props.justificationRequired &&
            (this.state.deleteJustification === undefined ||
                this.state.deleteJustification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to delete a member',
            });
            return;
        }
        this.api
            .deleteRoleMember(
                domain,
                this.state.deleteName,
                this.state.deleteJustification
                    ? this.state.deleteJustification
                    : 'deleted using Athenz UI',
                this.props._csrf
            )
            .then(() => {
                this.loadRoleByUser();
                this.setState({
                    showDelete: false,
                    showSuccess: true,
                    errorMessage: null,
                });
                setTimeout(
                    () =>
                        this.setState({
                            showSuccess: false,
                        }),
                    MODAL_TIME_OUT
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onSubmitDelete(domain) {
        if (
            this.props.justificationRequired &&
            (this.state.deleteJustification === undefined ||
                this.state.deleteJustification.trim() === '')
        ) {
            this.setState({
                errorMessage:
                    'Justification is required to delete a member from roles',
            });
            return;
        }
        this.api
            .deleteMember(
                domain,
                this.state.deleteName,
                this.state.deleteMemberName,
                this.state.deleteJustification
                    ? this.state.deleteJustification
                    : 'deleted using Athenz UI',
                this.props._csrf
            )
            .then(() => {
                this.loadRoleByUser();
                this.setState({
                    showDelete: false,
                    showSuccess: true,
                    errorMessage: null,
                });
                setTimeout(
                    () =>
                        this.setState({
                            showSuccess: false,
                        }),
                    MODAL_TIME_OUT
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    deleteRoleCancel() {
        this.setState({
            showDelete: false,
            deleteName: '',
        });
    }

    saveJustification(val) {
        this.setState({ deleteJustification: val });
    }

    expandRole(memberName) {
        let expand = this.state.expand;
        const center = 'center';
        const left = 'left';
        let content = this.state.contents;
        let expandArray = this.state.expandTable;
        if (content[memberName] !== null) {
            content[memberName] = null;
            expandArray[memberName] = false;
            this.setState({
                contents: content,
                expandTable: expandArray,
            });
        } else {
            content[memberName] = expand[memberName].map((role, i) => {
                let deleteItem = this.deleteItem.bind(
                    this,
                    role.roleName,
                    memberName
                );
                let color = '';
                if (i % 2 === 0) {
                    color = colors.row;
                }
                return (
                    <tr key={role.roleName}>
                        <TDStyled color={color} align={left}>
                            {role.roleName}
                        </TDStyled>
                        <TDStyled color={color} align={center}>
                            {role.expiration
                                ? this.dateUtils.getLocalDate(
                                      role.expiration,
                                      'UTC',
                                      'UTC'
                                  )
                                : null}
                        </TDStyled>
                        <TDStyledSub color={color} align={center}>
                            <Icon
                                icon={'trash'}
                                onClick={deleteItem}
                                color={colors.icons}
                                isLink
                                size={'1.25em'}
                                verticalAlign={'text-bottom'}
                            />
                        </TDStyledSub>
                    </tr>
                );
            });
            expandArray[memberName] = true;
            this.setState({
                contents: content,
                expandTable: expandArray,
            });
        }
    }

    loadRoleByUser() {
        this.api
            .getRoleMembers(this.props.domain)
            .then((members) => {
                let expand = {};
                let contents = {};
                let expandArray = {};
                let fullNameArr = {};
                for (let i = 0; i < members.members.length; i++) {
                    let name = members.members[i].memberName;
                    expand[name] = members.members[i].memberRoles;
                    fullNameArr[name] = members.members[i].memberFullName;
                    contents[name] = null;
                    expandArray[name] = false;
                }
                this.setState({
                    list: members,
                    loaded: 'done',
                    expand: expand,
                    contents: contents,
                    expandTable: expandArray,
                    fullNames: fullNameArr,
                });
            })
            .catch((err) => {
                let message;
                if (err.statusCode === 0) {
                    message = 'Okta expired. Please refresh the page';
                } else {
                    message = `Status: ${err.statusCode}. Message: ${err.body.message}`;
                }
                this.setState({
                    errorMessage: message,
                });
            });
    }

    onCloseAlert() {
        this.setState({
            showSuccess: false,
        });
    }

    render() {
        const { domain } = this.props;
        const center = 'center';
        const left = 'left';
        let deleteCancel = this.deleteRoleCancel.bind(this);
        let submitDelete = this.onSubmitDelete.bind(this, domain);
        let submitDeleteMember = this.onSubmitDeleteMember.bind(this, domain);
        let closeSuccess = this.onCloseAlert.bind(this);
        if (this.state.loaded === 'todo') {
            return <div data-testid='userroletable' />;
        }
        const rows =
            this.state.list.members &&
            this.state.list.members
                .sort((a, b) => {
                    return a.memberName.localeCompare(b.memberName);
                })
                .map((item, i) => {
                    let deleteItem = this.deleteItemMember.bind(
                        this,
                        item.memberName
                    );
                    let expandRole = this.expandRole.bind(
                        this,
                        item.memberName
                    );
                    let color = '';
                    if (i % 2 === 0) {
                        color = colors.row;
                    }

                    let toReturn = [];
                    toReturn.push(
                        <tr key={item.memberName}>
                            <TDStyled color={color} align={left}>
                                <LeftMarginSpan>
                                    <Icon
                                        icon={'arrowhead-down-circle-solid'}
                                        onClick={expandRole}
                                        color={colors.icons}
                                        isLink
                                        size={'1em'}
                                        verticalAlign={'text-bottom'}
                                    />
                                </LeftMarginSpan>
                                {item.memberName +
                                    (this.state.fullNames[item.memberName] !==
                                    undefined
                                        ? ' (' +
                                          this.state.fullNames[
                                              item.memberName
                                          ] +
                                          ')'
                                        : '') +
                                    ' (' +
                                    item.memberRoles.length +
                                    ')'}
                            </TDStyled>
                            <TDStyled color={color} align={center} />
                            <TDStyled color={color} align={center}>
                                <Icon
                                    icon={'trash'}
                                    onClick={deleteItem}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </TDStyled>
                        </tr>
                    );
                    toReturn.push(
                        <tr>
                            <RoleUserTable
                                showTable={
                                    this.state.expandTable[item.memberName]
                                }
                            >
                                {this.state.contents[item.memberName]}
                            </RoleUserTable>
                        </tr>
                    );
                    return toReturn;
                });

        return (
            <StyleTable data-testid='userroletable'>
                <thead>
                    {this.state.showSuccess ? (
                        <Alert
                            isOpen={this.state.showSuccess}
                            title={
                                this.state.deleteMember
                                    ? 'Successfully deleted member from all roles'
                                    : 'Successfully deleted member from role '
                            }
                            type='success'
                            onClose={closeSuccess}
                        />
                    ) : null}
                    <tr>
                        <TableHeadStyled align={left}>MEMBER</TableHeadStyled>
                        <TableHeadStyledUser align={center}>
                            Expiration Date
                        </TableHeadStyledUser>
                        <TableHeadStyledUser align={center}>
                            Delete
                        </TableHeadStyledUser>
                    </tr>
                </thead>
                <DeleteModal
                    name={this.state.deleteName}
                    isOpen={this.state.showDelete}
                    cancel={deleteCancel}
                    submit={
                        this.state.deleteMember
                            ? submitDeleteMember
                            : submitDelete
                    }
                    message={
                        this.state.deleteMember
                            ? 'Are you sure you want to permanently delete the Member from all roles: '
                            : 'Are you sure you want to permanently delete the Member from Role: '
                    }
                    showJustification={this.props.justificationRequired}
                    onJustification={this.saveJustification}
                    errorMessage={this.state.errorMessage}
                />
                {rows}
            </StyleTable>
        );
    }
}
