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

export default class DomainDetails extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            showOnBoardToAWSModal: false,
            showSuccess: false,
        };
        this.closeModal = this.closeModal.bind(this);
        this.onClickOnboardToAWS = this.onClickOnboardToAWS.bind(this);
        this.toggleOnboardToAWSModal = this.toggleOnboardToAWSModal.bind(this);
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
                </DetailsDiv>
            </DomainSectionDiv>
        );
    }
}
