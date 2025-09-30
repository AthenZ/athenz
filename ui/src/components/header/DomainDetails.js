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
import styled from '@emotion/styled';
import DateUtils from '../utils/DateUtils';
import AppUtils from '../utils/AppUtils';
import React from 'react';
import Button from '../denali/Button';
import Switch from '../denali/Switch';
import Alert from '../denali/Alert';
import {
    MODAL_TIME_OUT,
    ENVIRONMENT_DROPDOWN_OPTIONS,
    ONCALL_URL,
} from '../constants/constants';
import AddModal from '../modal/AddModal';
import RequestUtils from '../utils/RequestUtils';
import { colors } from '../denali/styles';
import { connect } from 'react-redux';
import {
    selectDomainAuditEnabled,
    selectDomainData,
} from '../../redux/selectors/domainData';
import {
    selectProductMasterLink,
    selectTimeZone,
} from '../../redux/selectors/domains';
import { makeRolesExpires } from '../../redux/actions/roles';
import { makePoliciesExpires } from '../../redux/actions/policies';
import Icon from '../denali/icons/Icon';
import AddPoc from '../member/AddPoc';
import { selectAllUsers } from '../../redux/selectors/user';
import AddEnvironmentModal from '../modal/AddEnvironmentModal';
import AddSlackChannelModal from '../modal/AddSlackChannelModal';
import OnCallTeamModal from '../modal/OnCallTeamModal';

const DomainSectionDiv = styled.div`
    margin: 20px 0;
`;

const DetailsDiv = styled.div`
    display: flex;
    flex-flow: row nowrap;
    margin: 20px 0;
`;

const SectionDiv = styled.div`
    padding-right: 50px;
    flex-basis: 15%;
`;

const ValueDiv = styled.div`
    font-weight: 600;
`;

const LabelDiv = styled.div`
    color: #9a9a9a;
    font-size: 12px;
    text-transform: uppercase;
`;

const StyledAnchorDiv = styled.div`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

const DivStyledOnCallTeam = styled.div`
    font-weight: 600;
    title: ${(props) => props.title};
    word-break: break-all;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 400px;
    display: flex;
`;

const StyledAnchor = styled.a`
    color: ${colors.linkActive};
    text-decoration: none;
    cursor: pointer;
    font-weight: '';
`;

const IconContainer = styled.div`
    cursor: pointer;
    margin-left: 5px;
`;

class DomainDetails extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            showOnBoardToAWSModal: false,
            showSuccess: false,
            showOnCallModal: false,
            onCall: this.props.domainDetails.onCall,
            category: 'domain',
            errorMessageForModal: '',
            errorMessage: null,
            showError: false,
            showPoc: false,
            showEnvironment: false,
            showSecurityPoc: false,
            poc: AppUtils.getSafe(
                () => this.props.domainDetails.contacts['product-owner'],
                'add'
            ),
            securityPoc: AppUtils.getSafe(
                () => this.props.domainDetails.contacts['security-owner'],
                'add'
            ),
            expandedDomain: false,
            environmentName: this.props.domainDetails.environment || 'add',
            slackChannel: this.props.domainDetails.slackChannel || 'add',
        };
        this.showError = this.showError.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.onClickOnboardToAWS = this.onClickOnboardToAWS.bind(this);
        this.toggleOnboardToAWSModal = this.toggleOnboardToAWSModal.bind(this);
        this.saveJustification = this.saveJustification.bind(this);
    }

    showError(errorMessage) {
        this.setState({
            showError: true,
            errorMessage: errorMessage,
        });
    }

    onClickPointOfContact(pointOfContact, contactType) {
        if (contactType === 'product-owner') {
            this.setState({
                showPoc: true,
                tempPocName: pointOfContact,
            });
        } else {
            // contactType = 'security-owner'
            this.setState({
                showSecurityPoc: true,
                tempSecurityPocName: pointOfContact,
            });
        }
    }

    onClickSlackChannel() {
        this.setState({
            showSlackChannelModal: true,
        });
    }

    onClickOnCallTeamModal() {
        this.setState({
            showOnCallModal: true,
        });
    }

    onUpdateOnCallTeamSuccessCb(teamName) {
        this.setState({
            showOnCallModal: false,
            onCall: teamName,
            showSuccess: true,
            successMessage: 'Successfully updated on call team',
        });

        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                }),
            MODAL_TIME_OUT + 1000
        );
    }

    onSlackChannelUpdateSuccessCb(slackChannelName) {
        let newState = {
            showSlackChannelModal: false,
            showSuccess: true,
        };

        if (!!!slackChannelName) {
            slackChannelName = 'add';
        }
        newState.slackChannel = slackChannelName;
        newState.successMessage = 'Successfully updated Slack channel';
        this.setState(newState);
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                }),
            MODAL_TIME_OUT + 1000
        );
    }

    onClickSlackChannelCancel() {
        this.setState({
            showSlackChannelModal: false,
            errorMessage: null,
            errorMessageForModal: '',
        });
    }

    onClickOnCallTeamCancel() {
        this.setState({
            showOnCallModal: false,
            errorMessage: null,
            errorMessageForModal: '',
        });
    }

    onClickPointOfContactCancel() {
        this.setState({
            showPoc: false,
            showSecurityPoc: false,
            errorMessage: null,
            errorMessageForModal: '',
        });
    }

    onClickEnvironment() {
        this.setState({
            showEnvironment: true,
        });
    }

    onClickEnvironmentCancel() {
        this.setState({
            showEnvironment: false,
            errorMessage: null,
            errorMessageForModal: '',
        });
    }

    saveJustification(val) {
        this.setState({
            auditRef: val,
        });
    }

    onClickOnboardToAWS() {
        this.api
            .applyAWSTemplates(
                this.props.domainDetails.name,
                'AWS Template applied from UI',
                this.props._csrf
            )
            .then((data) => {
                this.setState({
                    successMessage:
                        'Successfully onboarded to AWS. Please reload the page to view the updates.',
                    showSuccess: true,
                    showOnBoardToAWSModal: false,
                });

                // if template boarded, the policies and roles sorted in the store is out of date
                this.props.makeRolesAndPoliciesExpires();

                // this is to close the success alert
                setTimeout(
                    () =>
                        this.setState({
                            showSuccess: false,
                        }),
                    MODAL_TIME_OUT + 1000
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    toggleOnboardToAWSModal() {
        this.setState({
            showOnBoardToAWSModal: !this.state.showOnBoardToAWSModal,
        });
    }

    closeModal() {
        this.setState({ showSuccess: null });
    }

    expandDomain() {
        this.setState({
            expandedDomain: !this.state.expandedDomain,
        });
    }

    onPocUpdateSuccessCb(contactType, pocName) {
        let newState = {
            showPoc: false,
            showSecurityPoc: false,
            showSuccess: true,
        };
        if (contactType === 'product-owner') {
            newState.poc = pocName;
            newState.successMessage = 'Successfully added Point of Contact';
        } else {
            newState.securityPoc = pocName;
            newState.successMessage =
                'Successfully added Security Point of Contact';
        }
        this.setState(newState);
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                }),
            MODAL_TIME_OUT + 1000
        );
    }

    getCurrentContacts() {
        // Start with existing contacts to preserve any other contact types
        const currentContacts = { ...this.props.domainDetails.contacts } || {};

        // Update with current local state values
        if (this.state.poc && this.state.poc !== 'add') {
            currentContacts['product-owner'] = this.state.poc;
        }
        if (this.state.securityPoc && this.state.securityPoc !== 'add') {
            currentContacts['security-owner'] = this.state.securityPoc;
        }

        return currentContacts;
    }

    onEnvironmentUpdateSuccessCb(environmentName) {
        this.setState({
            showEnvironment: false,
            showSuccess: true,
            environmentName: environmentName,
            successMessage: 'Successfully updated the domain environment',
        });
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                }),
            MODAL_TIME_OUT + 1000
        );
    }

    render() {
        const arrowup = 'arrowhead-up-circle-solid';
        const arrowdown = 'arrowhead-down-circle';
        let expandDomain = this.expandDomain.bind(this);
        let localDate = new DateUtils();
        let modifiedDate = localDate.getLocalDate(
            this.props.domainDetails.modified,
            this.props.timeZone,
            this.props.timeZone
        );
        let showOnBoardToAWS = false;
        if (
            this.props.domainDetails.account &&
            !this.props.domainDetails.isAWSTemplateApplied
        ) {
            showOnBoardToAWS = true;
        }
        let onCallTeam = this.state?.onCall || 'add';
        let onCallTeamLink = this.state?.onCall
            ? `${ONCALL_URL}/${onCallTeam}`
            : '';

        if (this.state.showError) {
            return (
                <Alert
                    isOpen={this.state.showError}
                    title={this.state.errorMessage}
                    onClose={() => {}}
                    type='danger'
                />
            );
        }
        let pocObject = {};
        let securityPocObject = {};
        if ((this.state.poc || this.state.securityPoc) && this.props.userList) {
            this.props.userList.find((user) => {
                let fullName = 'user.' + user.login;
                if (fullName === this.state.poc) {
                    pocObject = user;
                }
                if (fullName === this.state.securityPoc) {
                    securityPocObject = user;
                }
            });
        }
        let onClickPointOfContact = this.onClickPointOfContact.bind(
            this,
            this.state.poc,
            'product-owner'
        );
        let onClickSecurityPointOfContact = this.onClickPointOfContact.bind(
            this,
            this.state.poc,
            'security-owner'
        );
        let onClickSlackChannel = this.onClickSlackChannel.bind(this);
        let contactType;
        let pocName;
        let openPocModal;
        if (this.state.showPoc) {
            openPocModal = true;
            contactType = 'product-owner';
            pocName = this.state.poc;
        } else if (this.state.showSecurityPoc) {
            openPocModal = true;
            contactType = 'security-owner';
            pocName = this.state.securityPoc;
        }
        let pocModal = openPocModal ? (
            <AddPoc
                domain={this.props.domainDetails.name}
                isOpen={openPocModal}
                onCancel={this.onClickPointOfContactCancel.bind(this)}
                errorMessage={this.state.errorMessageForModal}
                pocName={pocName}
                contactType={contactType}
                onPocUpdateSuccessCb={this.onPocUpdateSuccessCb.bind(this)}
                csrf={this.props._csrf}
                contacts={this.getCurrentContacts()}
                api={this.api}
            />
        ) : (
            ''
        );
        let environmentModal = this.state.showEnvironment ? (
            <AddEnvironmentModal
                domain={this.props.domainDetails.name}
                title='Environment'
                isOpen={this.state.showEnvironment}
                cancel={this.onClickEnvironmentCancel.bind(this)}
                errorMessage={this.state.errorMessageForModal}
                onEnvironmentUpdateSuccessCb={this.onEnvironmentUpdateSuccessCb.bind(
                    this
                )}
                csrf={this.props._csrf}
                api={this.api}
                environmentName={this.state.environmentName}
                environment={this.props.domainDetails.environment}
                dropDownOptions={ENVIRONMENT_DROPDOWN_OPTIONS}
            />
        ) : (
            ''
        );

        let slackChannelModal = this.state.showSlackChannelModal ? (
            <AddSlackChannelModal
                domain={this.props.domainDetails.name}
                title='Slack Channel'
                isOpen={this.state.showSlackChannelModal}
                onCancel={this.onClickSlackChannelCancel.bind(this)}
                errorMessage={this.state.errorMessageForModal}
                onSlackChannelUpdateSuccessCb={this.onSlackChannelUpdateSuccessCb.bind(
                    this
                )}
                slackChannelName={this.state.slackChannel}
                csrf={this.props._csrf}
                api={this.api}
            />
        ) : (
            ''
        );

        let onCallTeamModal = this.state.showOnCallModal ? (
            <OnCallTeamModal
                domain={this.props.domainDetails.name}
                title='OnCall Team'
                isOpen={this.state.showOnCallModal}
                onCancel={this.onClickOnCallTeamCancel.bind(this)}
                errorMessage={this.state.errorMessageForModal}
                onUpdateOnCallTeamSuccessCb={this.onUpdateOnCallTeamSuccessCb.bind(
                    this
                )}
                onCallTeamName={this.state.onCall}
                csrf={this.props._csrf}
                api={this.api}
            />
        ) : (
            ''
        );

        return (
            <DomainSectionDiv data-testid='domain-details'>
                <DetailsDiv>
                    <SectionDiv>
                        <DivStyledOnCallTeam>
                            <StyledAnchor
                                data-testid='poc-link'
                                onClick={onClickPointOfContact}
                            >
                                {pocObject.name || 'add'}
                            </StyledAnchor>
                        </DivStyledOnCallTeam>
                        <LabelDiv>POINT OF CONTACT</LabelDiv>
                    </SectionDiv>
                    <SectionDiv>
                        <DivStyledOnCallTeam>
                            <StyledAnchor
                                data-testid='security-poc-link'
                                onClick={onClickSecurityPointOfContact}
                            >
                                {securityPocObject.name || 'add'}
                            </StyledAnchor>
                        </DivStyledOnCallTeam>
                        <LabelDiv>SECURITY POINT OF CONTACT</LabelDiv>
                    </SectionDiv>
                    <SectionDiv>
                        <ValueDiv>{modifiedDate}</ValueDiv>
                        <LabelDiv>MODIFIED DATE</LabelDiv>
                    </SectionDiv>
                    <SectionDiv>
                        <ValueDiv>
                            <Switch
                                name={'auditDomainDetails'}
                                value={this.props.auditEnabled}
                                checked={this.props.auditEnabled}
                                disabled
                            />
                        </ValueDiv>
                        <LabelDiv>AUDIT ENABLED</LabelDiv>
                    </SectionDiv>
                    <SectionDiv>
                        <ValueDiv>
                            {this.props.domainDetails.account
                                ? this.props.domainDetails.account
                                : 'N/A'}
                        </ValueDiv>
                        <LabelDiv>AWS ACCOUNT ID</LabelDiv>
                    </SectionDiv>
                    <SectionDiv>
                        <ValueDiv>
                            {this.props.domainDetails.gcpProject
                                ? this.props.domainDetails.gcpProject
                                : 'N/A'}
                        </ValueDiv>
                        <LabelDiv>GCP PROJECT ID</LabelDiv>
                    </SectionDiv>
                    <ValueDiv>More Details</ValueDiv>
                    <IconContainer>
                        <Icon
                            icon={
                                this.state.expandedDomain ? arrowup : arrowdown
                            }
                            dataWdio={'domain-details-expand-icon'}
                            onClick={expandDomain}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                        />
                    </IconContainer>
                    {showOnBoardToAWS && (
                        <SectionDiv>
                            <Button
                                secondary
                                onClick={this.toggleOnboardToAWSModal}
                            >
                                Onboard to AWS
                            </Button>
                        </SectionDiv>
                    )}
                    {this.state.showOnBoardToAWSModal ? (
                        <AddModal
                            isOpen={this.state.showOnBoardToAWSModal}
                            cancel={this.toggleOnboardToAWSModal}
                            submit={this.onClickOnboardToAWS}
                            title={'Onboard domain to AWS'}
                            errorMessage={this.state.errorMessage}
                            sections={''}
                        />
                    ) : null}
                    {this.state.showSuccess ? (
                        <Alert
                            isOpen={this.state.showSuccess}
                            title={this.state.successMessage}
                            onClose={this.closeModal}
                            type='success'
                        />
                    ) : null}
                    {pocModal}
                    {onCallTeamModal}
                    {environmentModal}
                    {slackChannelModal}
                </DetailsDiv>
                {this.state.expandedDomain ? (
                    <DetailsDiv>
                        <SectionDiv>
                            <ValueDiv>
                                {this.props.domainDetails.productId ? (
                                    <StyledAnchorDiv
                                        data-testid='pm-id'
                                        onClick={() =>
                                            window.open(
                                                this.props.productMasterLink
                                                    .url +
                                                    this.props.domainDetails
                                                        .productId,
                                                this.props.productMasterLink
                                                    .target
                                            )
                                        }
                                    >
                                        {this.props.domainDetails.productId}
                                    </StyledAnchorDiv>
                                ) : (
                                    'N/A'
                                )}
                            </ValueDiv>
                            <LabelDiv>Product ID</LabelDiv>
                        </SectionDiv>
                        <SectionDiv>
                            <ValueDiv>
                                {this.props.domainDetails.org
                                    ? this.props.domainDetails.org
                                    : 'N/A'}
                            </ValueDiv>
                            <LabelDiv>ORGANIZATION</LabelDiv>
                        </SectionDiv>
                        <SectionDiv>
                            <DivStyledOnCallTeam title={onCallTeam}>
                                {onCallTeam === 'add' ? (
                                    <StyledAnchor
                                        onClick={this.onClickOnCallTeamModal.bind(
                                            this
                                        )}
                                        data-testid='add-oncall-team'
                                    >
                                        {onCallTeam}
                                    </StyledAnchor>
                                ) : (
                                    <>
                                        <StyledAnchor
                                            href={onCallTeamLink}
                                            data-testid='oncall-team-link'
                                        >
                                            {onCallTeam}
                                        </StyledAnchor>
                                        <IconContainer>
                                            <Icon
                                                size='16px'
                                                icon={'pencil'}
                                                onClick={this.onClickOnCallTeamModal.bind(
                                                    this
                                                )}
                                                dataWdio='edit-oncall-team'
                                            />
                                        </IconContainer>
                                    </>
                                )}
                            </DivStyledOnCallTeam>
                            <LabelDiv>ONCALL TEAM</LabelDiv>
                        </SectionDiv>
                        <SectionDiv>
                            <DivStyledOnCallTeam
                                title={this.state.environmentName}
                            >
                                <StyledAnchor
                                    onClick={this.onClickEnvironment.bind(this)}
                                >
                                    {this.state.environmentName}
                                </StyledAnchor>
                            </DivStyledOnCallTeam>
                            <LabelDiv>ENVIRONMENT</LabelDiv>
                        </SectionDiv>
                        <SectionDiv>
                            <DivStyledOnCallTeam
                                title={this.state.slackChannel}
                            >
                                <StyledAnchor
                                    data-testid='add-slack-channel'
                                    onClick={this.onClickSlackChannel.bind(
                                        this
                                    )}
                                >
                                    {this.state.slackChannel}
                                </StyledAnchor>
                            </DivStyledOnCallTeam>
                            <LabelDiv>SLACK CHANNEL</LabelDiv>
                        </SectionDiv>
                    </DetailsDiv>
                ) : null}
            </DomainSectionDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        domainDetails: selectDomainData(state),
        productMasterLink: selectProductMasterLink(state),
        auditEnabled: selectDomainAuditEnabled(state),
        timeZone: selectTimeZone(state),
        userList: selectAllUsers(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    makeRolesAndPoliciesExpires: () => {
        dispatch(makeRolesExpires());
        dispatch(makePoliciesExpires());
    },
});

export default connect(mapStateToProps, mapDispatchToProps)(DomainDetails);
