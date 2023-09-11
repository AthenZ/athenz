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
import { colors } from '../denali/styles';
import Button from '../denali/Button';
import PolicyRow from './PolicyRow';
import Alert from '../denali/Alert';
import DeleteModal from '../modal/DeleteModal';
import AddModal from '../modal/AddModal';
import NameUtils from '../utils/NameUtils';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';
import InputLabel from '../denali/InputLabel';
import Input from '../denali/Input';
import AppUtils from '../utils/AppUtils';
import {
    addPolicy,
    deletePolicy,
    duplicatePolicyVersion,
} from '../../redux/thunks/policies';
import { connect } from 'react-redux';
import AddPolicy from './AddPolicy';
import { selectPolicies } from '../../redux/selectors/policies';
import { selectIsLoading } from '../../redux/selectors/loading';
import { selectTimeZone } from '../../redux/selectors/domains';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';
import { arrayEquals } from '../utils/ArrayUtils';

const PolicySectionDiv = styled.div`
    margin: 20px;
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

const AddContainerDiv = styled.div`
    padding-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-flow: row nowrap;
    float: right;
`;

const PolicyTable = styled.table`
    width: 100%;
    border-spacing: 0 15px;
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

export class PolicyList extends React.Component {
    constructor(props) {
        super(props);
        this.onSubmitDeletePolicy = this.onSubmitDeletePolicy.bind(this);
        this.onCancelDeletePolicy = this.onCancelDeletePolicy.bind(this);
        this.onSubmitDuplicatePolicy = this.onSubmitDuplicatePolicy.bind(this);
        this.onCancelDuplicatePolicy = this.onCancelDuplicatePolicy.bind(this);
        this.toggleAddPolicy = this.toggleAddPolicy.bind(this);
        this.reloadPolicies = this.reloadPolicies.bind(this);
        this.closeModals = this.closeModals.bind(this);
        this.policyListToMap = this.policyListToMap.bind(this);
        this.state = {
            policiesMap:
                (props.policies && this.policyListToMap(props.policies)) || [],
            showAddPolicy: false,
            showDelete: false,
            deletePolicyName: null,
            showDuplicatePolicy: false,
            duplicatePolicyName: null,
            duplicateVersionSourceName: null,
            duplicateVersionName: null,
        };
    }

    componentDidUpdate = (prevProps) => {
        if (!arrayEquals(prevProps.policies, this.props.policies)) {
            this.setState({
                policiesMap: this.policyListToMap(this.props.policies),
            });
        }
    };

    policyListToMap(policies) {
        let policyList = policies || [];
        return policyList.reduce(function (map, obj) {
            if (!map[obj.name]) {
                map[obj.name] = [];
            }

            map[obj.name].push(obj);
            return map;
        }, {});
    }

    onSubmitDeletePolicy() {
        const { deletePolicy } = this.props;

        deletePolicy(
            this.props.domain,
            this.state.deletePolicyName,
            this.props._csrf
        )
            .then(() => {
                let showSuccess = true;
                let successMessage = `Successfully deleted policy ${this.state.deletePolicyName}`;
                this.setState({
                    showSuccess,
                    successMessage,
                    showAddPolicy: false,
                    showDelete: false,
                    showDuplicatePolicy: false,
                });
                // this is to close the success alert
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

    onSubmitDuplicatePolicy() {
        this.props
            .duplicatePolicyVersion(
                this.props.domain,
                this.state.duplicatePolicyName,
                this.state.duplicateVersionSourceName,
                this.state.duplicateVersionName,
                this.props._csrf
            )
            .then(() => {
                this.state.reloadPolicyVersionsFunc(
                    'duplicatePolicyVersion',
                    false,
                    `${this.state.duplicatePolicyName}` +
                        '-' +
                        `${this.state.duplicateVersionName}`,
                    this.closeModals
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onCancelDeletePolicy() {
        this.setState({
            showDelete: false,
            deletePolicyName: null,
        });
    }

    onCancelDuplicatePolicy() {
        this.setState({
            showDuplicatePolicy: false,
            duplicatePolicyName: null,
            duplicateVersionName: null,
            reloadPolicyVersionsFunc: null,
        });
    }

    onClickDeletePolicy(policyName) {
        this.setState({
            showDelete: true,
            deletePolicyName: policyName,
            errorMessage: null,
        });
    }

    onClickDuplicatePolicyVersion(
        policyName,
        version,
        reloadPolicyVersionsFunc
    ) {
        this.setState({
            showDuplicatePolicy: true,
            duplicatePolicyName: policyName,
            duplicateVersionSourceName: version,
            reloadPolicyVersionsFunc: reloadPolicyVersionsFunc,
            errorMessage: null,
        });
    }

    closeModals(showSuccess, successMessage) {
        this.setState({
            showSuccess,
            successMessage,
            showAddPolicy: false,
            showDelete: false,
            showDuplicatePolicy: false,
        });
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                }),
            MODAL_TIME_OUT
        );
    }
    reloadPolicies(successMessage, showSuccess) {
        this.setState({
            // policiesMap: this.policyListToMap(this.props.policies),
            showAddPolicy: false,
            showSuccess,
            successMessage,
            showDelete: false,
            showDuplicatePolicy: false,
        });
        // this is to close the success alert
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                }),
            MODAL_TIME_OUT
        );
    }

    toggleAddPolicy() {
        this.setState({
            showAddPolicy: !this.state.showAddPolicy,
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

    render() {
        const { domain } = this.props;
        const left = 'left';
        const center = 'center';
        const policyNames = Object.keys(this.state.policiesMap);
        const rows = policyNames.map((policyName, i) => {
            let item = AppUtils.deepClone(
                this.state.policiesMap[policyName][0]
            );
            let activeVersion = this.state.policiesMap[policyName].find(
                (x) => x.active
            );
            // policy modified date of the active version
            item.modified = activeVersion.modified;
            // polciy row will be considered the active version (for assertions)
            item.version = activeVersion.version;
            const name = NameUtils.getShortName(':policy.', item.name);
            let onClickDeletePolicy = this.onClickDeletePolicy.bind(this, name);
            let onClickDuplicatePolicyVersion =
                this.onClickDuplicatePolicyVersion.bind(this, name);
            let newPolicy = name === this.state.successMessage;
            return (
                <PolicyRow
                    name={name}
                    isActive={true}
                    version={item.version}
                    policies={this.props.policies}
                    policyVersions={this.state.policiesMap[policyName]}
                    domain={domain}
                    modified={item.modified}
                    duplicatePolicyVersion={this.props.duplicatePolicyVersion}
                    key={item.name + '-' + item.version}
                    _csrf={this.props._csrf}
                    onClickDeletePolicy={onClickDeletePolicy}
                    onClickDuplicatePolicyVersion={
                        onClickDuplicatePolicyVersion
                    }
                    newPolicy={newPolicy}
                    rowInVersionGroup={'single'}
                    enableDelete={true}
                    enableDuplicate={
                        this.state.policiesMap[policyName].length < 3
                    }
                    isChild={false}
                    timeZone={this.props.timeZone}
                />
            );
        });
        let addPolicy = this.state.showAddPolicy ? (
            <AddPolicy
                showAddPolicy={this.state.showAddPolicy}
                onCancel={this.toggleAddPolicy}
                onSubmit={this.props.addPolicy}
                domain={domain}
                _csrf={this.props._csrf}
            />
        ) : (
            ''
        );
        let versionNameChanged = this.inputChanged.bind(
            this,
            'duplicateVersionName'
        );
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
        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading policies'} />
        ) : (
            <PolicySectionDiv data-testid='policylist'>
                <AddContainerDiv>
                    <div>
                        <Button secondary onClick={this.toggleAddPolicy}>
                            Add Policy
                        </Button>
                        {addPolicy}
                    </div>
                </AddContainerDiv>
                <PolicyTable>
                    <thead>
                        <tr>
                            <TableHeadStyled align={center}>
                                Active
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>
                                Policy
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>
                                Versions
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>
                                Modified Date
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                Rules
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                Tags
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                Duplicate
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                Delete
                            </TableHeadStyled>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </PolicyTable>
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={() => this.closeModals(false)}
                        type='success'
                    />
                ) : null}
                {this.state.showDelete ? (
                    <DeleteModal
                        name={this.state.deletePolicyName}
                        isOpen={this.state.showDelete}
                        cancel={this.onCancelDeletePolicy}
                        submit={this.onSubmitDeletePolicy}
                        errorMessage={this.state.errorMessage}
                        message={
                            'Are you sure you want to permanently delete the Policy '
                        }
                    />
                ) : null}
                {this.state.showDuplicatePolicy ? (
                    <AddModal
                        isOpen={this.state.showDuplicatePolicy}
                        cancel={this.onCancelDuplicatePolicy}
                        submit={this.onSubmitDuplicatePolicy}
                        errorMessage={this.state.errorMessage}
                        title={`Add version to ${this.state.duplicatePolicyName} based on version ${this.state.duplicateVersionSourceName}`}
                        sections={sections}
                        overflowY={'auto'}
                    />
                ) : null}
            </PolicySectionDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        policies: selectPolicies(state),
        timeZone: selectTimeZone(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    duplicatePolicyVersion: (
        domain,
        duplicatePolicyName,
        duplicateVersionSourceName,
        duplicateVersionName,
        _csrf
    ) =>
        dispatch(
            duplicatePolicyVersion(
                domain,
                duplicatePolicyName,
                duplicateVersionSourceName,
                duplicateVersionName,
                _csrf
            )
        ),
    deletePolicy: (domainName, policyName, _csrf) =>
        dispatch(deletePolicy(domainName, policyName, _csrf)),
    addPolicy: (
        domain,
        policyName,
        role,
        resource,
        action,
        effect,
        caseSensitive,
        _csrf
    ) =>
        dispatch(
            addPolicy(
                domain,
                policyName,
                role,
                resource,
                action,
                effect,
                caseSensitive,
                _csrf
            )
        ),
});

export default connect(mapStateToProps, mapDispatchToProps)(PolicyList);
