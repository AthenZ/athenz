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
import React, { useState, useEffect } from 'react';
import styled from '@emotion/styled';
import Button from '../denali/Button';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import AddMember from './AddMember';
import PaginatedMemberTable from './PaginatedMemberTable';
import MemberFilter from './MemberFilter';
import { selectIsLoading } from '../../redux/selectors/loading';
import { selectTimeZone } from '../../redux/selectors/domains';
import { connect } from 'react-redux';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';
import { useMemberPagination } from '../../hooks/useMemberPagination';
import API from '../../api';

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

const MemberList = (props) => {
    const [showAddMember, setShowAddMember] = useState(false);
    const [showSuccess, setShowSuccess] = useState(false);
    const [successMessage, setSuccessMessage] = useState('');
    const [errorMessage, setErrorMessage] = useState(null);
    const [paginationEnabled, setPaginationEnabled] = useState(true);

    const api = API();

    const toggleAddMember = () => {
        setShowAddMember(!showAddMember);
    };

    const reloadMembers = (successMessage, showSuccessParam = true) => {
        setShowAddMember(false);
        setShowSuccess(showSuccessParam);
        setSuccessMessage(successMessage);
        setErrorMessage(null);
        setTimeout(() => {
            setShowSuccess(false);
            setSuccessMessage('');
        }, MODAL_TIME_OUT);
    };

    const closeModal = () => {
        setShowSuccess(false);
    };

    // Prepare members data
    const { domain, collection, collectionDetails, members = [] } = props;

    // Fetch page feature flag for pagination with caching
    useEffect(() => {
        let isMounted = true;

        api.getPageFeatureFlag('memberList')
            .then((data) => {
                if (isMounted && data && typeof data.pagination === 'boolean') {
                    setPaginationEnabled(data.pagination);
                }
            })
            .catch((err) => {
                // On error, default to enabled (fail safe)
                console.warn(
                    'Failed to fetch memberList page feature flag:',
                    err
                );
                if (isMounted) {
                    setPaginationEnabled(true);
                }
            });

        return () => {
            isMounted = false;
        };
    }, []); // Empty dependency array for proper caching

    // Unified pagination hook that handles filtering, sorting, and pagination
    const memberPagination = useMemberPagination(
        members,
        collectionDetails,
        paginationEnabled,
        '' // initial filter
    );

    const justificationReq =
        props.isDomainAuditEnabled ||
        collectionDetails.reviewEnabled ||
        collectionDetails.selfServe;

    const addMember = showAddMember ? (
        <AddMember
            category={props.category}
            domainName={props.domain}
            collection={props.collection}
            onSubmit={reloadMembers}
            onCancel={toggleAddMember}
            _csrf={props._csrf}
            showAddMember={showAddMember}
            justificationRequired={justificationReq}
        />
    ) : null;

    const addMemberButton = (
        <AddContainerDiv>
            <div>
                <Button secondary onClick={toggleAddMember}>
                    Add Member
                </Button>
                {addMember}
            </div>
        </AddContainerDiv>
    );

    // Configuration objects for cleaner prop passing
    const sharedTableConfig = {
        category: props.category,
        domain,
        collection,
        timeZone: props.timeZone,
        _csrf: props._csrf,
        onSubmit: reloadMembers,
        justificationRequired: justificationReq,
        newMember: successMessage,
    };

    const paginationConfig = {
        pageSizeOptions: memberPagination.pageSizeOptions,
        onPageSizeChange: memberPagination.onPageSizeChange,
    };

    if (props.isLoading.length !== 0) {
        return <ReduxPageLoader message={'Loading members'} />;
    }

    return (
        <MembersSectionDiv data-testid='member-list'>
            {addMemberButton}

            {/* Member Filter */}
            {paginationEnabled && members.length > 0 && (
                <MemberFilter
                    value={memberPagination.filterText}
                    onChange={memberPagination.setFilterText}
                    testId='member-filter'
                />
            )}

            {/* Approved Members Table */}
            <PaginatedMemberTable
                memberData={memberPagination.approvedMembers}
                paginationConfig={paginationConfig}
                tableConfig={{
                    ...sharedTableConfig,
                    caption: 'Approved',
                }}
                testIdPrefix='approved'
            />

            <br />

            {/* Pending Members Table - only show if there are pending members */}
            {memberPagination.pendingMembers.totalItems > 0 && (
                <PaginatedMemberTable
                    memberData={memberPagination.pendingMembers}
                    paginationConfig={paginationConfig}
                    tableConfig={{
                        ...sharedTableConfig,
                        pending: true,
                        caption: 'Pending',
                    }}
                    testIdPrefix='pending'
                />
            )}

            {showSuccess && (
                <Alert
                    isOpen={showSuccess}
                    title={successMessage}
                    onClose={closeModal}
                    type='success'
                />
            )}
        </MembersSectionDiv>
    );
};

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        timeZone: selectTimeZone(state),
    };
};

export default connect(mapStateToProps)(MemberList);
