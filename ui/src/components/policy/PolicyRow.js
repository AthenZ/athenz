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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import styled from '@emotion/styled';
import PolicyRuleTable from './PolicyRuleTable';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';
import { css, keyframes } from '@emotion/react';
import { MODAL_TIME_OUT } from '../constants/constants';
import Alert from '../denali/Alert';
import DeleteModal from '../modal/DeleteModal';
import AddModal from '../modal/AddModal';
import InputLabel from '../denali/InputLabel';
import Input from '../denali/Input';
import RadioButton from '../denali/RadioButton';
import {
    deletePolicyVersion,
    getPolicyVersion,
    setActivePolicyVersion,
} from '../../redux/thunks/policies';
import { connect } from 'react-redux';
import { withRouter } from 'next/router';

const TdStyled = styled.td`
    text-align: ${(props) => props.align};
    padding: ${(props) => (props.padding ? props.padding : '5px 0 5px 15px')};
    vertical-align: middle;
    word-break: break-all;
    width: ${(props) => props.width};
`;

const TrStyled = styled.tr`
    ${(props) =>
        props.isSuccess === true &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
`;

const TrStyledPolicy = styled.tr`
    box-sizing: border-box;
    margin-top: 10px;
    box-shadow: 0 1px 4px #d9d9d9;
    box-shadow: ${(props) => {
        if (props.rowInVersionGroup == 'single') {
            return '0 1px 4px #d9d9d9';
        } else if (props.rowInVersionGroup == 'first') {
            return '0 1px 4px #f9f9f5';
        } else if (props.rowInVersionGroup == 'middle') {
            return '0 2px 3px #f9f9f5';
        } else if (props.rowInVersionGroup == 'last') {
            return '0 3px 3px #d9d9d9';
        } else {
            return '0 1px 4px #d9d9d9';
        }
    }};
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    padding: 5px 0 5px 15px;
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

const SectionDiv = styled.div`
    align-items: flex-start;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 30px;
`;

const StyledInputLabel = styled(InputLabel)`
    flex: 0 0 100px;
    margin-right: 2%;
`;

const StyledInput = styled(Input)`
    width: 500px;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin-right: 10px;
`;

const SectionsDiv = styled.div`
    width: 100%;
    text-align: left;
    background-color: ${colors.white};
`;

const PolicyVersionsTable = styled.table`
    width: 100%;
    border-spacing: 0 0;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid rgb(213, 213, 213);
    color: rgb(154, 154, 154);
    padding-bottom: 5px;
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;

export class PolicyRow extends React.Component {
    constructor(props) {
        super(props);
        this.toggleAssertions = this.toggleAssertions.bind(this);
        this.onSubmitDeletePolicyVersion =
            this.onSubmitDeletePolicyVersion.bind(this);
        this.onCancelDeletePolicyVersion =
            this.onCancelDeletePolicyVersion.bind(this);
        this.onSubmitDuplicatePolicyVersion =
            this.onSubmitDuplicatePolicyVersion.bind(this);
        this.onCancelDuplicatePolicyVersion =
            this.onCancelDuplicatePolicyVersion.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.onSetActive = this.onSetActive.bind(this);

        this.reLoadPolicyVersions = this.reLoadPolicyVersions.bind(this);
        this.state = {
            expanded: false,
            policyVersions: this.props.policyVersions,
            errorMessage: null,
            showDelete: false,
            deletePolicyName: null,
            deleteVersionName: null,
            showDuplicatePolicyVersion: false,
            duplicatePolicyName: null,
            duplicateVersionSourceName: null,
            duplicateVersionName: null,
            rowInVersionGroup: this.props.rowInVersionGroup,
            version: this.props.version,
            isActive: this.props.isActive,
            newPolicy: this.props.newPolicy,
            modified: this.props.modified,
            enableDelete: this.props.enableDelete,
            enableDuplicate: this.props.enableDuplicate,
            isChild: this.props.isChild,
        };
        this.localDate = new DateUtils();
    }

    toggleAssertions() {
        if (this.state.assertions) {
            this.setState({ assertions: null });
        } else {
            this.props
                .getPolicyVersion(
                    this.props.domain,
                    this.props.name,
                    this.state.version
                )
                .then((policyVersion) => {
                    this.setState({
                        assertions: policyVersion.assertions,
                        errorMessage: null,
                    });
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        }
    }

    onSetActive() {
        this.props
            .setActivePolicyVersion(
                this.props.domain,
                this.props.name,
                this.state.version,
                this.props._csrf
            )
            .then(() => {
                this.props.reloadPolicyVersionsFunc(
                    'setActivePolicyVersion',
                    false,
                    `${this.props.name}` + '-' + `${this.state.version}`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    expandVersions() {
        let expanded = this.state.expanded;
        this.setState({
            rowInVersionGroup: !expanded ? 'first' : 'single',
            assertions: !expanded ? this.state.assertions : null,
            enableDelete: expanded || !this.state.isActive,
            expanded: !expanded,
            newPolicy: false,
            successMessage: '',
        });
    }

    closeModal() {
        this.setState({ showSuccess: null });
    }

    reLoadPolicyVersions(type, showSuccess, successMessage, closeModalsFunc) {
        // Get policy versions
        const fullPolicyName = this.props.domain + ':policy.' + this.props.name;
        let policyVersions = this.props.policies.filter(function (
            policyVersion
        ) {
            return policyVersion.name === fullPolicyName;
        });
        // Get active version
        let activeVersion = policyVersions.find((x) => x.active);
        // If new active version was set -> only show the new active version and highlight the row
        let expanded =
            policyVersions.length > 1 && type !== 'setActivePolicyVersion';
        let newPolicy = type === 'setActivePolicyVersion';
        let assertions =
            type === 'setActivePolicyVersion' ? null : this.state.assertions;
        let rowInVersionGroup = this.state.rowInVersionGroup;
        // If expanded and there are more than one version, shadows should be in "first row of group" mode
        if (expanded && policyVersions.length > 1) {
            rowInVersionGroup = 'first';
        } else if (!expanded) {
            // If not expanded, shadows should be in "closed version group" mode
            rowInVersionGroup = 'single';
        }
        let enableDelete = !expanded;
        const maxPolicyVersions = 3;
        let enableDuplicate = policyVersions.length < maxPolicyVersions;
        let newState = {
            policyVersions: policyVersions,
            showSuccess,
            successMessage,
            showDelete: false,
            showDuplicatePolicyVersion: false,
            expanded: expanded,
            isActive: activeVersion.active,
            version: activeVersion.version,
            modified: activeVersion.modified,
            newPolicy,
            rowInVersionGroup,
            enableDelete,
            assertions,
            enableDuplicate,
        };

        if (closeModalsFunc) {
            this.setState(
                newState,
                closeModalsFunc(showSuccess, successMessage)
            );
        } else {
            this.setState(newState);
            // this is to close the success alert
            setTimeout(
                () =>
                    this.setState({
                        showSuccess: false,
                    }),
                MODAL_TIME_OUT
            );
        }
    }

    onSubmitDeletePolicyVersion() {
        this.props
            .deletePolicyVersion(
                this.props.domain,
                this.state.deletePolicyName,
                this.state.deleteVersionName,
                this.props._csrf
            )
            .then(() => {
                this.reLoadPolicyVersions(
                    'deletePolicyVersion',
                    false,
                    `${this.state.deletePolicyName}` +
                        '-' +
                        `${this.state.deleteVersionName}`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onSubmitDuplicatePolicyVersion() {
        this.props
            .duplicatePolicyVersion(
                this.props.domain,
                this.state.duplicatePolicyName,
                this.state.duplicateVersionSourceName,
                this.state.duplicateVersionName,
                this.props._csrf
            )
            .then(() => {
                this.reLoadPolicyVersions(
                    'duplicatePolicyVersion',
                    false,
                    `${this.state.duplicatePolicyName}` +
                        '-' +
                        `${this.state.duplicateVersionName}`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onCancelDeletePolicyVersion() {
        this.setState({
            showDelete: false,
            deletePolicyName: null,
            deleteVersionName: null,
        });
    }

    onCancelDuplicatePolicyVersion() {
        this.setState({
            showDuplicatePolicyVersion: false,
            duplicatePolicyName: null,
            duplicateVersionName: null,
        });
    }

    onClickDeletePolicyVersion(policyName, version) {
        this.setState({
            showDelete: true,
            deletePolicyName: policyName,
            deleteVersionName: version,
            errorMessage: null,
        });
    }

    onClickDuplicatePolicyVersion(policyName, version) {
        this.setState({
            showDuplicatePolicyVersion: true,
            duplicatePolicyName: policyName,
            duplicateVersionSourceName: version,
            errorMessage: null,
        });
    }

    inputChanged(key, evt) {
        let value = '';
        if (evt.target) {
            value = evt.target.value;
        } else {
            value = evt ? evt : '';
        }
        this.setState({ [key]: value });
    }

    onClickFunction(route) {
        this.props.router.push(route, route);
    }

    render() {
        let clickTag = this.onClickFunction.bind(
            this,
            `/domain/${this.props.domain}/policy/${this.props.name}/${this.props.version}/tags`
        );
        let rows = [];
        let left = 'left';
        let center = 'center';
        let displayName = this.state.isActive ? this.props.name : '';
        let displayVersion =
            !this.state.isActive ||
            this.state.version !== '0' ||
            (this.state.policyVersions && this.state.policyVersions.length > 1)
                ? this.state.version
                : '';
        let displayExpandButton =
            this.state.isActive &&
            this.state.policyVersions &&
            this.state.policyVersions.length > 1;
        const arrowup = 'arrowhead-up-circle-solid';
        const arrowdown = 'arrowhead-down-circle';
        let expandVersions = this.expandVersions.bind(this);
        let versionNameChanged = this.inputChanged.bind(
            this,
            'duplicateVersionName'
        );
        let rowInVersionGroup = this.state.rowInVersionGroup;
        if (this.state.assertions && rowInVersionGroup === 'last') {
            rowInVersionGroup = 'middle';
        }
        let sections = (
            <SectionsDiv>
                <SectionDiv>
                    <StyledInputLabel>Version Name</StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            placeholder='Enter Version Name'
                            onChange={versionNameChanged}
                            noanim
                            fluid
                        />
                    </ContentDiv>
                </SectionDiv>
            </SectionsDiv>
        );
        rows.push(
            <TrStyledPolicy
                key={this.props.name + '-' + this.state.version + '-row'}
                data-testid='policy-row'
                isSuccess={this.state.newPolicy}
                rowInVersionGroup={rowInVersionGroup}
            >
                {/*Active*/}
                <TdStyled align={center} width={'10%'}>
                    <RadioButton
                        name={
                            this.props.name +
                            '-' +
                            this.state.version +
                            '-active-' +
                            this.state.isActive
                        }
                        value='active'
                        checked={this.state.isActive}
                        onChange={this.onSetActive}
                        disabled={!this.state.expanded && this.state.isActive}
                    />
                </TdStyled>
                {/*Policy*/}
                <TdStyled align={left} width={'20%'}>
                    {displayName}
                </TdStyled>
                {/*Versions*/}
                <TdStyled align={left} width={'15%'} padding={'5px 0 5px 0'}>
                    <PolicyVersionsTable>
                        <thead></thead>
                        <tbody>
                            <tr>
                                <TdStyled align={'left'} width={'70%'}>
                                    {displayVersion}
                                </TdStyled>
                                <TdStyled align={'left'} width={'30%'}>
                                    {displayExpandButton ? (
                                        <Icon
                                            icon={
                                                this.state.expanded
                                                    ? arrowup
                                                    : arrowdown
                                            }
                                            onClick={expandVersions}
                                            color={colors.icons}
                                            isLink
                                            size={'1.25em'}
                                            verticalAlign={'text-bottom'}
                                        />
                                    ) : null}
                                </TdStyled>
                            </tr>
                        </tbody>
                    </PolicyVersionsTable>
                </TdStyled>
                {/*Modified Date*/}
                <TdStyled align={left} width={'20%'}>
                    {this.localDate.getLocalDate(
                        this.state.modified,
                        this.props.timeZone,
                        this.props.timeZone
                    )}
                </TdStyled>
                {/*Rules*/}
                <TdStyled align={center} width={'10%'}>
                    <Icon
                        icon={'list-check'}
                        onClick={this.toggleAssertions}
                        color={colors.icons}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                </TdStyled>
                {/*Tags*/}
                <TdStyled align={center} width={'10%'}>
                    <Icon
                        icon={'tag'}
                        onClick={clickTag}
                        color={colors.icons}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                </TdStyled>
                {/*Duplicate*/}
                <TdStyled align={center} width={'10%'}>
                    {(this.props.isChild && this.props.enableDuplicate) ||
                    (!this.props.isChild && this.state.enableDuplicate) ? (
                        <Icon
                            icon={'duplicate'}
                            onClick={() =>
                                this.props.onClickDuplicatePolicyVersion(
                                    this.state.version,
                                    this.reLoadPolicyVersions
                                )
                            }
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            viewBoxWidth={'48'}
                            viewBoxHeight={'48'}
                            verticalAlign={'text-bottom'}
                        />
                    ) : (
                        <Icon
                            icon={'duplicate'}
                            color={colors.grey500}
                            size={'1.25em'}
                            viewBoxWidth={'48'}
                            viewBoxHeight={'48'}
                            verticalAlign={'text-bottom'}
                            disabled={true}
                            title={
                                'You have created the maximum number of versions allowed.'
                            }
                            enableTitle={true}
                        />
                    )}
                </TdStyled>
                {/*Delete*/}
                <TdStyled align={center} width={'15%'}>
                    {this.state.enableDelete ? (
                        <Icon
                            icon={'trash'}
                            onClick={() =>
                                this.props.onClickDeletePolicy(
                                    this.state.version
                                )
                            }
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                            enableTitle={false}
                        />
                    ) : (
                        <Icon
                            icon={'trash-disabled'}
                            viewBoxWidth={'48'}
                            viewBoxHeight={'48'}
                            color={colors.grey500}
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                            disabled={true}
                            title={
                                'you can not delete a version that is active. Please change active version to delete this version'
                            }
                            enableTitle={true}
                        />
                    )}
                </TdStyled>
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal}
                        type='success'
                    />
                ) : null}
                {this.state.showDelete ? (
                    <DeleteModal
                        name={
                            this.state.deletePolicyName +
                            ' version ' +
                            this.state.deleteVersionName
                        }
                        isOpen={this.state.showDelete}
                        cancel={this.onCancelDeletePolicyVersion}
                        submit={this.onSubmitDeletePolicyVersion}
                        errorMessage={this.state.errorMessage}
                        message={
                            'Are you sure you want to permanently delete the Policy '
                        }
                    />
                ) : null}
                {this.state.showDuplicatePolicyVersion ? (
                    <AddModal
                        isOpen={this.state.showDuplicatePolicyVersion}
                        cancel={this.onCancelDuplicatePolicyVersion}
                        submit={this.onSubmitDuplicatePolicyVersion}
                        errorMessage={this.state.errorMessage}
                        title={`Add version to ${this.state.duplicatePolicyName} based on version ${this.state.duplicateVersionSourceName}`}
                        sections={sections}
                        overflowY={'auto'}
                    />
                ) : null}
            </TrStyledPolicy>
        );
        if (this.state.assertions) {
            rows.push(
                <TrStyled
                    key={this.props.name + '-' + this.state.version + '-info'}
                >
                    <PolicyRuleTable
                        assertions={this.state.assertions}
                        name={this.props.name}
                        version={this.state.version}
                        domain={this.props.domain}
                        _csrf={this.props._csrf}
                    />
                </TrStyled>
            );
        }
        // If clicked on show all versions, create a new table with the current row and the other policy versions
        if (this.state.expanded) {
            let otherVersions = this.state.policyVersions.filter(function (
                policyVersion
            ) {
                return !policyVersion.active;
            });
            let lastIndex = otherVersions.length - 1;
            otherVersions.map((item, i) => {
                let onClickDeletePolicyVersion =
                    this.onClickDeletePolicyVersion.bind(this, this.props.name);
                let onClickDuplicatePolicyVersion =
                    this.onClickDuplicatePolicyVersion.bind(
                        this,
                        this.props.name
                    );
                let newPolicy =
                    this.props.name + '-' + item.version ===
                    this.state.successMessage;
                let rowInVersionGroup = 'middle';
                if (i === lastIndex) {
                    rowInVersionGroup = 'last';
                }
                rows.push(
                    <PolicyRow
                        name={this.props.name}
                        version={item.version}
                        policies={this.props.policies}
                        isActive={false}
                        domain={this.props.domain}
                        modified={item.modified}
                        key={this.props.name + '-' + item.version}
                        _csrf={this.props._csrf}
                        onClickDeletePolicy={onClickDeletePolicyVersion}
                        onClickDuplicatePolicyVersion={
                            onClickDuplicatePolicyVersion
                        }
                        newPolicy={newPolicy}
                        reloadPolicyVersionsFunc={this.reLoadPolicyVersions}
                        getPolicyVersion={this.props.getPolicyVersion}
                        setActivePolicyVersion={
                            this.props.setActivePolicyVersion
                        }
                        rowInVersionGroup={rowInVersionGroup}
                        enableDelete={true}
                        enableDuplicate={this.state.enableDuplicate}
                        isChild={true}
                        router={this.props.router}
                        timeZone={this.props.timeZone}
                    />
                );
            });
            let versionsTable = [];
            versionsTable.push(
                <TrStyledPolicy
                    key={
                        this.props.name +
                        '-' +
                        this.state.version +
                        '-version-group'
                    }
                >
                    <td colSpan={7}>
                        <PolicyVersionsTable>
                            <thead></thead>
                            <tbody>{rows}</tbody>
                        </PolicyVersionsTable>
                    </td>
                </TrStyledPolicy>
            );
            return versionsTable;
        }
        return rows;
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
    };
};

const mapDispatchToProps = (dispatch) => ({
    setActivePolicyVersion: (domain, name, version, _csrf) =>
        dispatch(setActivePolicyVersion(domain, name, version, _csrf)),
    deletePolicyVersion: (domain, deletePolicyName, deleteVersionName, _csrf) =>
        dispatch(
            deletePolicyVersion(
                domain,
                deletePolicyName,
                deleteVersionName,
                _csrf
            )
        ),
    getPolicyVersion: (domain, policy, version) =>
        dispatch(getPolicyVersion(domain, policy, version)),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps
)(withRouter(PolicyRow));
