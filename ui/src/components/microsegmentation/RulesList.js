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
import { DnToggle } from '@denali-design/react';
// import 'denali-css/css/denali.css';
import { connect } from 'react-redux';
import {
    selectInboundOutboundList,
    selectInboundOutboundListWithFilter,
} from '../../redux/selectors/microsegmentation';
import AddSegmentation from './AddSegmentation';
import RuleTable from './RuleTable';
import { getInboundOutbound } from '../../redux/thunks/microsegmentation';
import GroupTable from './GroupTable';
import { selectDomainAuditEnabled } from '../../redux/selectors/domainData';
import { selectIsLoading } from '../../redux/selectors/loading';
import { selectFeatureFlag } from '../../redux/selectors/domains';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';

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

const StyledToggleDiv = styled.div`
    margin-right: 10px;
`;

class RulesList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            errorMessage: null,
            showAddSegmentation: false,
            tabularView: true,
            graphicalView: false,
        };
        this.toggleAddSegmentation = this.toggleAddSegmentation.bind(this);
        this.toggleView = this.toggleView.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.reloadData = this.reloadData.bind(this);
    }

    toggleAddSegmentation() {
        this.setState({
            showAddSegmentation: !this.state.showAddSegmentation,
        });
    }

    toggleView(evt) {
        switch (evt.target.name) {
            case 'tabular':
                this.setState({
                    tabularView: true,
                    graphicalView: false,
                });
                break;
            case 'graphical':
                this.setState({
                    tabularView: false,
                    graphicalView: true,
                });
                break;
        }
    }

    reloadData() {
        this.props
            .getInboundOutbound(this.props.domain)
            .then(() => {
                this.setState({
                    // segmentationData: this.props.data,
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
                pageFeatureFlag={this.props.pageFeatureFlag}
            />
        ) : (
            ''
        );

        addSegmentationButton = (
            <AddContainerDiv>
                <StyledToggleDiv>
                    <DnToggle isRadioToggle isSmall>
                        <DnToggle.RadioItem
                            defaultChecked={this.state.tabularView}
                            id='tabular'
                            isDisabled={false}
                            name='tabular'
                            radioLabel='Tabular'
                            radioValue='tabular'
                            onChange={this.toggleView}
                        />
                        <DnToggle.RadioItem
                            defaultChecked={this.state.graphicalView}
                            id='graphical'
                            isDisabled={false}
                            name='graphical'
                            radioLabel='Graphical'
                            radioValue='graphical'
                            onChange={this.toggleView}
                        />
                    </DnToggle>
                </StyledToggleDiv>
                <div>
                    <Button secondary onClick={this.toggleAddSegmentation}>
                        Add ACL Policy
                    </Button>
                    {addSegmentation}
                </div>
            </AddContainerDiv>
        );

        let showInbound =
            this.props.data &&
            this.props.data.inbound?.length > 0 &&
            this.state.tabularView;
        let showOutbound =
            this.props.data &&
            this.props.data.outbound?.length > 0 &&
            this.state.tabularView;

        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading microsegmentation data'} />
        ) : (
            <MembersSectionDiv data-testid='segmentation-data-list'>
                {addSegmentationButton}

                {showInbound ? (
                    <RuleTable
                        category={'inbound'}
                        domain={domain}
                        _csrf={this.props._csrf}
                        onSubmit={this.reloadData}
                        data={this.props.data.inbound}
                        caption='Inbound'
                        pageFeatureFlag={this.props.pageFeatureFlag}
                        api={this.api}
                    />
                ) : null}
                <br />
                {showOutbound ? (
                    <RuleTable
                        category={'outbound'}
                        domain={domain}
                        _csrf={this.props._csrf}
                        onSubmit={this.reloadData}
                        data={this.props.data.outbound}
                        caption='Outbound'
                        pageFeatureFlag={this.props.pageFeatureFlag}
                        api={this.api}
                    />
                ) : null}
                {!showInbound && !showOutbound && this.state.tabularView ? (
                    <div>
                        Use the Add ACL Policy button to add inbound and
                        outbound rules.
                    </div>
                ) : null}
                {this.state.graphicalView && (
                    <GroupTable
                        domain={domain}
                        api={this.api}
                        _csrf={this.props._csrf}
                        onSubmit={this.reloadData}
                        data={this.props.data}
                    />
                )}
            </MembersSectionDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        data: props.filterByService
            ? selectInboundOutboundListWithFilter(state, props.filterByService)
            : selectInboundOutboundList(state),
        isDomainAuditEnabled: selectDomainAuditEnabled(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getInboundOutbound: (domainName) =>
        dispatch(getInboundOutbound(domainName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(RulesList);
