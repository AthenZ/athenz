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
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import AddMember from './AddMember';
import MemberTable from './MemberTable';
import MemberFilter from './MemberFilter';
import Pagination from './Pagination';
import { selectIsLoading } from '../../redux/selectors/loading';
import { selectTimeZone } from '../../redux/selectors/domains';
import { connect } from 'react-redux';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';
import { arrayEquals } from '../utils/ArrayUtils';
import { useMemberFilter } from '../../hooks/useMemberFilter';
import { usePagination } from '../../hooks/usePagination';

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

function MemberList(props) {
    const { domain, collection, collectionDetails, members = [], isDomainAuditEnabled, category, timeZone, _csrf, isLoading } = props;
    
    // State management
    const [showAddMember, setShowAddMember] = React.useState(false);
    const [showSuccess, setShowSuccess] = React.useState(false);
    const [successMessage, setSuccessMessage] = React.useState('');
    const [localMembers, setLocalMembers] = React.useState(members);

    // Update local members when props change
    React.useEffect(() => {
        setLocalMembers(members);
    }, [members, collection, domain]);

    // Filter logic - separate approved and pending members
    const approvedMembers = React.useMemo(() => {
        if (collectionDetails.trust) {
            return localMembers;
        }
        return localMembers.filter((item) => item.approved);
    }, [localMembers, collectionDetails.trust]);

    const pendingMembers = React.useMemo(() => {
        if (collectionDetails.trust) {
            return [];
        }
        return localMembers.filter((item) => !item.approved);
    }, [localMembers, collectionDetails.trust]);

    // Pagination and filtering for approved members
    const {
        searchText: approvedSearchText,
        setSearchText: setApprovedSearchText,
        filteredMembers: filteredApprovedMembers,
        isFiltered: isApprovedFiltered,
        hasResults: hasApprovedResults
    } = useMemberFilter(approvedMembers, 200);

    const {
        currentPage: approvedCurrentPage,
        pageSize: approvedPageSize,
        displayedItems: displayedApprovedMembers,
        totalPages: approvedTotalPages,
        goToPage: goToApprovedPage,
        setPageSize: setApprovedPageSize
    } = usePagination(filteredApprovedMembers, 30);

    // Pagination and filtering for pending members
    const {
        searchText: pendingSearchText,
        setSearchText: setPendingSearchText,
        filteredMembers: filteredPendingMembers,
        isFiltered: isPendingFiltered,
        hasResults: hasPendingResults
    } = useMemberFilter(pendingMembers, 200);

    const {
        currentPage: pendingCurrentPage,
        pageSize: pendingPageSize,
        displayedItems: displayedPendingMembers,
        totalPages: pendingTotalPages,
        goToPage: goToPendingPage,
        setPageSize: setPendingPageSize
    } = usePagination(filteredPendingMembers, 30);

    // Event handlers
    const toggleAddMember = React.useCallback(() => {
        setShowAddMember(prev => !prev);
    }, []);

    const closeModal = React.useCallback(() => {
        setShowSuccess(false);
    }, []);

    const reloadMembers = React.useCallback((successMsg, showSuccessFlag = true) => {
        setShowAddMember(false);
        setShowSuccess(showSuccessFlag);
        setSuccessMessage(successMsg);
        
        setTimeout(() => {
            setShowSuccess(false);
            setSuccessMessage('');
        }, MODAL_TIME_OUT);
    }, []);

    // Computed values
    const justificationReq = isDomainAuditEnabled || collectionDetails.reviewEnabled || collectionDetails.selfServe;
    const showPending = pendingMembers.length > 0;

    // Render add member modal
    const addMember = showAddMember ? (
        <AddMember
            category={category}
            domainName={domain}
            collection={collection}
            onSubmit={reloadMembers}
            onCancel={toggleAddMember}
            _csrf={_csrf}
            showAddMember={showAddMember}
            justificationRequired={justificationReq}
        />
    ) : null;

    // Render add member button
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

    if (isLoading.length !== 0) {
        return <ReduxPageLoader message={'Loading members'} />;
    }

    return (
        <MembersSectionDiv data-testid='member-list'>
            {addMemberButton}
            
            {/* Approved Members Section */}
            <div data-testid='approved-members-section'>
                <MemberFilter
                    searchText={approvedSearchText}
                    onSearchChange={setApprovedSearchText}
                    pageSize={approvedPageSize}
                    onPageSizeChange={setApprovedPageSize}
                    hasResults={hasApprovedResults}
                    isFiltered={isApprovedFiltered}
                    totalItems={approvedMembers.length}
                    filteredCount={filteredApprovedMembers.length}
                />
                
                <MemberTable
                    category={category}
                    domain={domain}
                    collection={collection}
                    members={displayedApprovedMembers}
                    caption='Approved'
                    timeZone={timeZone}
                    _csrf={_csrf}
                    onSubmit={reloadMembers}
                    justificationRequired={justificationReq}
                    newMember={successMessage}
                />
                
                <Pagination
                    currentPage={approvedCurrentPage}
                    totalPages={approvedTotalPages}
                    onPageChange={goToApprovedPage}
                />
            </div>

            <br />

            {/* Pending Members Section */}
            {showPending && (
                <div data-testid='pending-members-section'>
                    <MemberFilter
                        searchText={pendingSearchText}
                        onSearchChange={setPendingSearchText}
                        pageSize={pendingPageSize}
                        onPageSizeChange={setPendingPageSize}
                        hasResults={hasPendingResults}
                        isFiltered={isPendingFiltered}
                        totalItems={pendingMembers.length}
                        filteredCount={filteredPendingMembers.length}
                    />
                    
                    <MemberTable
                        category={category}
                        domain={domain}
                        collection={collection}
                        members={displayedPendingMembers}
                        pending={true}
                        caption='Pending'
                        timeZone={timeZone}
                        _csrf={_csrf}
                        onSubmit={reloadMembers}
                        justificationRequired={justificationReq}
                        newMember={successMessage}
                    />
                    
                    <Pagination
                        currentPage={pendingCurrentPage}
                        totalPages={pendingTotalPages}
                        onPageChange={goToPendingPage}
                    />
                </div>
            )}

            {/* Success Alert */}
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
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        timeZone: selectTimeZone(state),
    };
};

export default connect(mapStateToProps)(MemberList);
