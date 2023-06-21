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
import DeleteModal from '../modal/DeleteModal';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';
import { css, keyframes } from '@emotion/react';
import { selectRoleUsers } from '../../redux/selectors/roles';
import { deleteMemberFromAllRoles } from '../../redux/thunks/roles';
import { connect } from 'react-redux';
import { deleteMember } from '../../redux/thunks/collections';
import { selectDomainAuditEnabled } from '../../redux/selectors/domainData';
import UserRoleRow from './UserRoleRow';

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

const LeftMarginSpan = styled.span`
    margin-right: 10px;
    vertical-align: bottom;
`;

const TDStyledMember = styled.div`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    width: 70%;
`;

const TDStyledIcon = styled.div`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    width: 15%;
`;

const TrStyled = styled.div`
    box-sizing: border-box;
    margin-top: 10px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    display: flex;
    ${(props) =>
        props.isSuccess === true &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
`;

const colorTransition = keyframes`
    0% {
        background-color: rgba(21, 192, 70, 0.20);
    }
    100% {
        background-color: transparent;
    }
`;

const StyledTd = styled.div`
    width: 100%;
`;

const StyledTable = styled.div`
    width: 100%;
`;

const StyledUserCol = styled.div`
    text-align: ${(props) => props.align};
    width: 70%;
`;

const StyledIconCol = styled.div`
    text-align: ${(props) => props.align};
    width: 15%;
`;

const FlexDiv = styled.div`
    display: flex;
`;
class UserRoleTable extends React.Component {
    constructor(props) {
        super(props);
        this.deleteRoleCancel = this.deleteRoleCancel.bind(this);
        this.saveJustification = this.saveJustification.bind(this);
        this.deleteItemMember = this.deleteItemMember.bind(this);
        this.deleteItem = this.deleteItem.bind(this);
        this.state = {
            list: {},
            loaded: 'done',
            expand: {},
            contents: {},
            showDelete: false,
            expandTable: {},
            showSuccess: false,
            searchText: props.searchText,
        };
        this.dateUtils = new DateUtils();
    }

    componentDidUpdate(prevProps) {
        if (prevProps.searchText !== this.props.searchText) {
            this.setState({
                searchText: this.props.searchText,
            });
        }
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
        this.props
            .deleteMemberFromAllRoles(
                domain,
                this.state.deleteName,
                this.state.deleteJustification
                    ? this.state.deleteJustification
                    : 'deleted using Athenz UI',
                this.props._csrf
            )
            .then(() => {
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
        this.props
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
        const rows = this.props.roleUsers
            ? this.props.roleUsers
                  .filter((member) => {
                      return member.memberName.includes(
                          this.state.searchText.trim()
                      );
                  })
                  .sort((a, b) => {
                      return a.memberName.localeCompare(b.memberName);
                  })
                  .map((item, i) => {
                      let newMember =
                          this.props.domain + '-' + item.memberName ===
                          this.props.newMember;
                      return (
                          <UserRoleRow
                              newMember={newMember}
                              memberData={item}
                              onDelete={this.deleteItemMember}
                              deleteRoleMember={this.deleteItem}
                              timeZone={this.props.timeZone}
                          />
                      );
                  })
            : [];
        return (
            <StyleTable key='user-role-table' data-testid='userroletable'>
                <TableHeadStyled>
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
                    <StyledUserCol align={left}>MEMBER</StyledUserCol>
                    <StyledIconCol align={center}>
                        Expiration Date
                    </StyledIconCol>
                    <StyledIconCol align={center}>Delete</StyledIconCol>
                </TableHeadStyled>
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

const mapStateToProps = (state, props) => {
    return {
        ...props,
        roleUsers: selectRoleUsers(state),
        justificationRequired: selectDomainAuditEnabled(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    deleteMember: (
        domainName,
        collectionName,
        memberName,
        justification,
        _csrf
    ) =>
        dispatch(
            deleteMember(
                domainName,
                collectionName,
                'role',
                memberName,
                justification,
                false,
                _csrf
            )
        ),
    deleteMemberFromAllRoles: (domainName, deleteName, auditRef, _csrf) =>
        dispatch(
            deleteMemberFromAllRoles(domainName, deleteName, auditRef, _csrf)
        ),
});

export default connect(mapStateToProps, mapDispatchToProps)(UserRoleTable);
