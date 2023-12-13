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
import API from '../../api';
import styled from '@emotion/styled';

import CollectionDetails from '../header/CollectionDetails';
import ReviewList from '../review/ReviewList';
import RequestUtils from '../utils/RequestUtils';
import NameHeader from '../header/NameHeader';
import Error from '../../pages/_error';
import { selectIsLoading } from '../../redux/selectors/loading';
import { getDomainData } from '../../redux/thunks/domain';
import { connect } from 'react-redux';
import {
    selectReviewRoleMembers,
    selectRole,
} from '../../redux/selectors/roles';
import { getRole } from '../../redux/thunks/roles';
import createCache from '@emotion/cache';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';
import { getGroup } from '../../redux/thunks/groups';
import {
    selectGroup,
    selectReviewGroupMembers,
} from '../../redux/selectors/groups';

const AppContainerDiv = styled.div`
    align-items: stretch;
    flex-flow: row nowrap;
    height: 100%;
    display: flex;
    justify-content: flex-start;
`;

const MainContentDiv = styled.div`
    flex: 1 1 calc(100vh - 60px);
    overflow: hidden;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const RolesContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const RolesContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
    border-radius: 25px 25px 0px 0px;
    background: linear-gradient(to top, #f2f2f2, #fff);
    padding: 20px 30px 10px;
`;

const ReviewContainer = styled.div`
    margin: 20px;
    border: 1px solid lightgrey;
    border-radius: 25px;
`;

class ReviewCard extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            error: null,
            reload: false,
        };
    }

    componentDidMount() {
        const {
            getRole,
            getGroup,
            getDomainData,
            domainName,
            name,
            userName,
            category,
        } = this.props;
        let promises = [getDomainData(domainName, userName)];
        if (category === 'group') {
            promises.push(getGroup(domainName, name));
        } else {
            promises.push(getRole(domainName, name));
        }
        Promise.all(promises).catch((err) => {
            let response = RequestUtils.errorCheckHelper(err);
            this.setState({
                error: response.error,
                reload: response.reload,
            });
        });
    }

    render() {
        const {
            domainName,
            reload,
            roleDetails,
            groupDetails,
            name,
            category,
            roleMembers,
            groupMembers,
            _csrf,
            isLoading,
        } = this.props;
        let members = category === 'group' ? groupMembers : roleMembers;
        let collectionDetails = Object.keys(roleDetails).length
            ? roleDetails
            : groupDetails;
        if (reload || this.state.reload) {
            window.location.reload();
            return <div />;
        }
        const err = this.props.error || this.state.error;
        if (err) {
            return <Error err={err} />;
        }

        return (
            <ReviewContainer data-testid='review'>
                <MainContentDiv>
                    <AppContainerDiv>
                        <RolesContainerDiv>
                            <RolesContentDiv>
                                <PageHeaderDiv>
                                    <NameHeader
                                        category={this.props.category}
                                        domain={domainName}
                                        collection={name}
                                        collectionDetails={collectionDetails}
                                    />
                                    <CollectionDetails
                                        collectionDetails={collectionDetails}
                                        _csrf={_csrf}
                                    />
                                </PageHeaderDiv>
                                <ReviewList
                                    domain={domainName}
                                    collection={name}
                                    collectionDetails={collectionDetails}
                                    members={members}
                                    _csrf={_csrf}
                                    category={this.props.category}
                                    justification={this.props.justification}
                                    isCardView={true}
                                    onSuccessReview={this.props.onSuccessReview}
                                />
                            </RolesContentDiv>
                        </RolesContainerDiv>
                    </AppContainerDiv>
                </MainContentDiv>
            </ReviewContainer>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        roleDetails: selectRole(state, props.domainName, props.name),
        roleMembers: selectReviewRoleMembers(
            state,
            props.domainName,
            props.name
        ),
        groupDetails: selectGroup(state, props.domainName, props.name),
        groupMembers: selectReviewGroupMembers(
            state,
            props.domainName,
            props.name
        ),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
    getRole: (domainName, roleName) => dispatch(getRole(domainName, roleName)),
    getGroup: (domainName, groupName) =>
        dispatch(getGroup(domainName, groupName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(ReviewCard);
