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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import NameUtils from '../utils/NameUtils';
import styled from '@emotion/styled';
import DeleteModal from '../modal/DeleteModal';
import Menu from '../denali/Menu/Menu';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const TrStyled = styled.tr`
    background-color: ${(props) => props.color};
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

const LeftSpan = styled.span`
    padding-left: 20px;
`;

export default class MemberRow extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.onSubmitDelete = this.onSubmitDelete.bind(this);
        this.onClickDeleteCancel = this.onClickDeleteCancel.bind(this);
        this.onReviewSubmit = this.onReviewSubmit.bind(this);
        this.state = {
            deleteName: this.props.details.memberName,
            showDelete: false,
        };
        this.localDate = new DateUtils();
    }

    onReviewSubmit(message) {
        this.setState({ reviewMembers: false });
        if (message) {
            this.props.onUpdateSuccess(message);
        }
    }

    saveJustification(val) {
        this.setState({ deleteJustification: val });
    }

    onClickDelete(name) {
        this.setState({
            showDelete: true,
            deleteName: name,
        });
    }

    onSubmitDelete(domain) {
        let roleName = this.props.role;
        if (
            this.props.justificationRequired &&
            (this.state.deleteJustification === undefined ||
                this.state.deleteJustification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to delete a role',
            });
            return;
        }

        this.api
            .deleteMember(
                domain,
                roleName,
                this.state.deleteName,
                this.state.deleteJustification
                    ? this.state.deleteJustification
                    : 'deleted using Athenz UI',
                this.props._csrf
            )
            .then(() => {
                this.setState({
                    showDelete: false,
                    deleteName: null,
                    deleteJustification: null,
                    errorMessage: null,
                });
                this.props.onUpdateSuccess(
                    `Successfully deleted role ${roleName}`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onClickDeleteCancel() {
        this.setState({
            showDelete: false,
            deleteName: '',
        });
    }

    render() {
        let rows = [];
        let left = 'left';
        let center = 'center';
        let member = this.props.details;
        let color = this.props.color;
        let idx = this.props.idx;

        let clickDelete = this.onClickDelete.bind(this, this.state.deleteName);
        let submitDelete = this.onSubmitDelete.bind(this, this.props.domain);
        let clickDeleteCancel = this.onClickDeleteCancel.bind(this);

        rows.push(
            <tr key={this.state.name} data-testid='member-row'>
                <TDStyled color={color} align={left}>
                    {member.memberName}
                </TDStyled>
                <TDStyled color={color} align={left}>
                    {member.memberFullName}
                </TDStyled>
                <TDStyled color={color} align={left}>
                    {member.expiration
                        ? this.localDate.getLocalDate(
                              member.expiration,
                              'UTC',
                              'UTC'
                          )
                        : 'N/A'}
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'trash'}
                                    onClick={clickDelete}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Delete Member</MenuDiv>
                    </Menu>
                </TDStyled>
            </tr>
        );

        if (this.state.showDelete) {
            rows.push(
                <DeleteModal
                    name={this.props.details.memberName}
                    isOpen={this.state.showDelete}
                    cancel={clickDeleteCancel}
                    submit={submitDelete}
                    key={this.props.details.memberName + '-delete'}
                    showJustification={this.props.justificationRequired}
                    message={
                        'Are you sure you want to permanently delete the Member '
                    }
                    onJustification={this.saveJustification}
                    errorMessage={this.state.errorMessage}
                />
            );
        }

        return rows;
    }
}
