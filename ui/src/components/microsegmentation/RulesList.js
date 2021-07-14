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
import Button from '../denali/Button';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';
import RuleTable from './RuleTable';
import AddSegmentation from './AddSegmentation';

const MembersSectionDiv = styled.div`
    margin: 20px;
`;

const AddContainerDiv = styled.div`
    padding-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-flow: row nowrap;
    float: right;
`;

export default class RulesList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            segmentationData: props.data,
            errorMessage: null,
            showAddSegmentation: false,
        };
        this.toggleAddSegmentation = this.toggleAddSegmentation.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.reloadData = this.reloadData.bind(this);
    }

    toggleAddSegmentation() {
        this.setState({
            showAddSegmentation: !this.state.showAddSegmentation,
        });
    }

    reloadData() {
        this.api
            .getInboundOutbound(this.props.domain)
            .then((data) => {
                this.setState({
                    segmentationData: data,
                    showAddSegmentation: false,
                    showAddStaticInstances: false,
                });
                setTimeout(
                    () =>
                        this.setState({
                            showSuccess: false,
                            successMessage: '',
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

    closeModal() {
        this.setState({ showSuccess: null });
    }

    render() {
        const { domain } = this.props;
        let addSegmentationButton = '';
        let addSegmentation = this.state.showAddSegmentation ? (
            <AddSegmentation
                api={this.api}
                domain={this.props.domain}
                onSubmit={this.reloadData}
                onCancel={this.toggleAddSegmentation}
                _csrf={this.props._csrf}
                showAddSegment={this.state.showAddSegmentation}
                justificationRequired={this.props.isDomainAuditEnabled}
            />
        ) : (
            ''
        );

        addSegmentationButton = (
            <AddContainerDiv>
                <div>
                    <Button secondary onClick={this.toggleAddSegmentation}>
                        Add ACL Policy
                    </Button>
                    {addSegmentation}
                </div>
            </AddContainerDiv>
        );

        let showInbound = this.state.segmentationData.inbound.length > 0;
        let showOutbound = this.state.segmentationData.outbound.length > 0;

        return (
            <MembersSectionDiv data-testid='segmentation-data-list'>
                {addSegmentationButton}

                {showInbound ? (
                    <RuleTable
                        category={'inbound'}
                        domain={domain}
                        api={this.api}
                        _csrf={this.props._csrf}
                        onSubmit={this.reloadData}
                        data={this.state.segmentationData.inbound}
                        caption='Inbound'
                        justificationRequired={this.props.isDomainAuditEnabled}
                    />
                ) : null}
                <br />
                {showOutbound ? (
                    <RuleTable
                        category={'outbound'}
                        domain={domain}
                        api={this.api}
                        _csrf={this.props._csrf}
                        onSubmit={this.reloadData}
                        data={this.state.segmentationData.outbound}
                        caption='Outbound'
                        justificationRequired={this.props.isDomainAuditEnabled}
                    />
                ) : null}
                {!showInbound && !showOutbound ? (
                    <div>
                        Use the Add ACL Policy button to add inbound and
                        outbound rules.
                    </div>
                ) : null}
            </MembersSectionDiv>
        );
    }
}
