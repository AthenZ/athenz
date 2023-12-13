/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
import React from 'react';
import { connect } from 'react-redux';
import TabGroup from '../denali/TabGroup';
import { withRouter } from 'next/router';
import { WORKFLOW_TABS } from '../constants/constants';
import PageUtils from '../utils/PageUtils';
import API from '../../api';
import { selectUserReviewRoles } from '../../redux/selectors/roles';
import { selectUserReviewGroups } from '../../redux/selectors/groups';
import { selectPendingMembersList } from '../../redux/selectors/domains';
import { getUserPendingMembers } from '../../redux/thunks/user';
import { getReviewRoles } from '../../redux/thunks/roles';
import { getReviewGroups } from '../../redux/thunks/groups';
import {
    WORKFLOW_PENDING_MEMBERS_APPROVAL_ADMIN_VIEW_TAB,
    WORKFLOW_ROLE_REVIEW,
    WORKFLOW_GROUP_REVIEW,
} from '../constants/constants';

class PendingApprovalTabs extends React.Component {
    constructor(props) {
        super(props);
        this.tabClicked = this.tabClicked.bind(this);
        this.api = API();
        this.state = {
            roleGroupReviewFeatureFlag: false,
        };
    }

    // TODO clean up feature flag when feature is done
    componentDidMount() {
        this.api.getPageFeatureFlag('roleGroupReview').then((data) => {
            this.setState({
                roleGroupReviewFeatureFlag: data['roleGroupReviewFeatureFlag'],
            });
        });
    }

    tabClicked(tab) {
        switch (tab.name) {
            case 'admin':
                this.props.router.push(PageUtils.workflowAdminPage());
                break;
            case 'domain':
                this.props.router.push(PageUtils.workflowDomainPage());
                break;
            case 'roleReview':
                this.props.router.push(PageUtils.workflowRoleReviewPage());
                break;
            case 'groupReview':
                this.props.router.push(PageUtils.workflowGroupReviewPage());
                break;
        }
    }

    render() {
        let shouldShowAllWorkflowTabs = this.state.roleGroupReviewFeatureFlag;
        let workflowTabs = shouldShowAllWorkflowTabs
            ? WORKFLOW_TABS
            : WORKFLOW_TABS.filter(
                  (tab) =>
                      tab.name !== 'roleReview' && tab.name !== 'groupReview'
              );
        workflowTabs.forEach((tab) => {
            if (
                this.props.reviewRoles.length > 0 &&
                tab.name === 'roleReview'
            ) {
                tab.label = WORKFLOW_ROLE_REVIEW + ` *`;
            } else if (
                this.props.reviewGroups.length > 0 &&
                tab.name === 'groupReview'
            ) {
                tab.label = WORKFLOW_GROUP_REVIEW + ` *`;
            } else if (
                Object.keys(this.props.pending).length > 0 &&
                tab.name === 'admin'
            ) {
                tab.label =
                    WORKFLOW_PENDING_MEMBERS_APPROVAL_ADMIN_VIEW_TAB + ` *`;
            }
        });
        return (
            <TabGroup
                tabs={workflowTabs}
                selectedName={this.props.selectedName}
                onClick={this.tabClicked}
                noanim
            />
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        reviewRoles: selectUserReviewRoles(state),
        reviewGroups: selectUserReviewGroups(state),
        pending: selectPendingMembersList(state, null, 'admin'),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getUserPendingMembers: () => dispatch(getUserPendingMembers()),
    getReviewRoles: () => dispatch(getReviewRoles()),
    getReviewGroups: () => dispatch(getReviewGroups()),
});
export default connect(
    mapStateToProps,
    mapDispatchToProps
)(withRouter(PendingApprovalTabs));
