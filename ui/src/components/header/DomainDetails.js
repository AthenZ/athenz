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
import styled from '@emotion/styled';
import DateUtils from '../utils/DateUtils';
import React from 'react';
import Button from '../denali/Button';
import Switch from '../denali/Switch';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import AddModal from '../modal/AddModal';
import RequestUtils from '../utils/RequestUtils';
import BusinessServiceModal from '../modal/BusinessServiceModal';
import { colors } from '../denali/styles';

const DomainSectionDiv = styled.div`
    margin: 20px 0;
`;

const DetailsDiv = styled.div`
    display: flex;
    flex-flow: row nowrap;
`;

const SectionDiv = styled.div`
    padding-right: 50px;
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

const DivStyledBusinessService = styled.div`
    font-weight: 600;
    title: ${(props) => props.title};
    word-break: break-all;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 400px;
`;

const StyledAnchor = styled.a`
    color: ${colors.linkActive};
    text-decoration: none;
    cursor: pointer;
    font-weight: '';
`;

export default class DomainDetails extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            showOnBoardToAWSModal: false,
            showSuccess: false,
            showBusinessService: false,
            businessServiceName: this.props.domainDetails.businessService,
            category: 'domain',
        };
        this.closeModal = this.closeModal.bind(this);
        this.onClickOnboardToAWS = this.onClickOnboardToAWS.bind(this);
        this.toggleOnboardToAWSModal = this.toggleOnboardToAWSModal.bind(this);
        this.saveBusinessService = this.saveBusinessService.bind(this);
        this.saveJustification = this.saveJustification.bind(this);
    }

    onClickBusinessService(domainName, businessServiceName, auditEnabled) {
        this.setState({
            showBusinessService: true,
            businessServiceName: businessServiceName,
            businessServiceDomainName: domainName,
            auditEnabled: auditEnabled,
            showDelete: false,
        });
    }

    onClickBusinessServiceCancel() {
        this.setState({
            showBusinessService: false,
            errorMessage: null,
            businessServiceName: '',
            businessServiceDomainName: '',
            auditRef: '',
            showDelete: false,
        });
    }

    saveJustification(val) {
        this.setState({
            auditRef: val,
        });
    }
    saveBusinessService(val) {
        this.setState({
            businessServiceName: val,
        });
    }

    updateMeta(meta, domainName, csrf, successMessage) {
        this.api
            .putMeta(
                domainName,
                domainName,
                meta,
                'Updated ' + domainName + ' Meta using Athenz UI',
                csrf,
                this.state.category
            )
            .then(() => {
                this.setState({
                    showDelete: false,
                    deleteName: null,
                    auditEnabled: false,
                    auditRef: '',
                    errorMessage: null,
                    showBusinessService: false,
                    businessServiceName: meta.businessService,
                    successMessage: successMessage,
                    showSuccess: true,
                });
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
                    showDelete: false,
                    deleteName: null,
                    auditEnabled: false,
                    auditRef: '',
                    showBusinessService: false,
                    businessServiceName: '',
                });
            });
    }

    onSubmitBusinessService() {
        let domainName = this.state.businessServiceDomainName;
        let businessServiceName = this.state.businessServiceName;
        let domainMeta = {};
        domainMeta.businessService = businessServiceName;
        let successMessage = `Successfully set business service for domain ${domainName}`;
        this.updateMeta(
            domainMeta,
            domainName,
            this.props._csrf,
            successMessage
        );
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

    render() {
        let localDate = new DateUtils();
        let modifiedDate = localDate.getLocalDate(
            this.props.domainDetails.modified,
            'UTC',
            'UTC'
        );
        let showOnBoardToAWS = false;
        if (
            this.props.domainDetails.account &&
            !this.props.domainDetails.isAWSTemplateApplied
        ) {
            showOnBoardToAWS = true;
        }
        let businessServiceItem = this.onClickBusinessService.bind(
            this,
            this.props.domainDetails.name,
            this.props.domainDetails.businessService,
            this.state.auditEnabled
        );
        let businessServiceTitle = this.state.businessServiceName
            ? this.state.businessServiceName
            : 'add';
        let clickBusinessServiceCancel =
            this.onClickBusinessServiceCancel.bind(this);
        let clickBusinessServiceSubmit =
            this.onSubmitBusinessService.bind(this);
        return (
            <DomainSectionDiv data-testid='domain-details'>
                <DetailsDiv>
                    <SectionDiv>
                        <ValueDiv>{modifiedDate}</ValueDiv>
                        <LabelDiv>MODIFIED DATE</LabelDiv>
                    </SectionDiv>
                    <SectionDiv>
                        <ValueDiv>
                            {this.props.domainDetails.ypmId ? (
                                <StyledAnchorDiv
                                    data-testid='pm-id'
                                    onClick={() =>
                                        window.open(
                                            this.props.productMasterLink.url +
                                                this.props.domainDetails.ypmId,
                                            this.props.productMasterLink.target
                                        )
                                    }
                                >
                                    {this.props.domainDetails.ypmId}
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
                        <ValueDiv>
                            <Switch
                                name={'auditDomainDetails'}
                                value={this.props.domainDetails.auditEnabled}
                                checked={this.props.domainDetails.auditEnabled}
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
                        <DivStyledBusinessService title={businessServiceTitle}>
                            <StyledAnchor onClick={businessServiceItem}>
                                {businessServiceTitle}
                            </StyledAnchor>
                        </DivStyledBusinessService>
                        <LabelDiv>BUSINESS SERVICE</LabelDiv>
                    </SectionDiv>
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
                    {this.state.showBusinessService ? (
                        <BusinessServiceModal
                            isOpen={this.state.showBusinessService}
                            cancel={clickBusinessServiceCancel}
                            businessServiceName={this.state.businessServiceName}
                            domainName={this.state.businessServiceDomainName}
                            submit={clickBusinessServiceSubmit}
                            showJustification={this.state.auditEnabled}
                            onJustification={this.saveJustification}
                            onBusinessService={this.saveBusinessService}
                            key={'business-service-modal'}
                            errorMessage={this.state.errorMessageForModal}
                            api={this.api}
                            userId={this.state.userId}
                            validBusinessServices={
                                this.props.validBusinessServices
                            }
                            validBusinessServicesAll={
                                this.props.validBusinessServicesAll
                            }
                        />
                    ) : null}
                </DetailsDiv>
            </DomainSectionDiv>
        );
    }
}
