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
import TagRow from './TagRow';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';
import DeleteModal from '../modal/DeleteModal';
import Button from '../denali/Button';
import AddTag from './AddTag';
import AppUtils from '../utils/AppUtils';
import { connect } from 'react-redux';
import { updateTags } from '../../redux/thunks/collections';
import { selectIsLoading } from '../../redux/selectors/loading';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';
const TagsSectionDiv = styled.div`
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
const TagTable = styled.table`
    width: 100%;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
    border-color: ${colors.grey600};
`;
const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;
class TagList extends React.Component {
    constructor(props) {
        super(props);
        AppUtils.bindClassMethods(this);
        this.state = {
            category: props.category,
            tags: props.tags || {},
            successMessage: '',
        };
    }
    openAddTag() {
        this.setState({
            showAddTag: true,
        });
    }
    closeAddTag() {
        this.setState({
            showAddTag: false,
            editMode: false,
            editedTagKey: '',
            editedTagValues: [],
            errorMessage: null,
        });
    }
    onClickEditTag(tagKey, tagValues) {
        this.setState({
            showAddTag: true,
            editMode: true,
            editedTagKey: tagKey,
            editedTagValues: tagValues,
        });
    }
    onCancelDeleteTag() {
        this.setState({
            showDelete: false,
            deleteTagName: null,
            deleteTagValue: null,
        });
    }
    onClickDeleteTag(tagName) {
        this.setState({
            showDelete: true,
            deleteTagName: tagName,
            errorMessage: null,
        });
    }
    onCancelDeleteTagValue() {
        this.setState({
            showDeleteTagValue: false,
            deleteTagName: null,
            deleteTagValue: null,
        });
    }
    onClickDeleteTagValue(tagKey, tagValue) {
        //its the last tag value - act as regular delete
        if (
            this.state.tags[tagKey].list.length === 1 &&
            this.state.tags[tagKey].list[0] === tagValue
        ) {
            this.onClickDeleteTag(tagKey);
        } else {
            this.setState({
                showDeleteTagValue: true,
                deleteTagName: tagKey,
                deleteTagValue: tagValue,
                errorMessage: null,
            });
        }
    }
    validateTagExist(tagName) {
        return this.state.tags && this.state.tags[tagName] != null;
    }
    addNewTag(tagKey, tagValues) {
        const csrf = this.props._csrf;
        let collectionMeta = this.metaObject(
            AppUtils.deepClone(this.props.collectionDetails),
            this.props.category
        );
        this.updateMetaOnAdd(collectionMeta, tagKey, tagValues, csrf);
    }
    updateMetaOnAdd(meta, tagKey, tagValues, csrf) {
        if (!meta.tags) {
            meta.tags = {};
        }
        meta.tags[tagKey] = {};
        meta.tags[tagKey].list = tagValues;
        let successMessage = tagKey;
        this.updateMeta(meta, csrf, successMessage, false);
    }

    onSubmitDeleteTag() {
        const csrf = this.props._csrf;
        let collectionMeta = this.metaObject(
            AppUtils.deepClone(this.props.collectionDetails),
            this.props.category
        );
        this.updateMetaOnDelete(collectionMeta, csrf);
    }
    updateMetaOnDelete(meta, csrf) {
        if (this.state.deleteTagValue) {
            //delete specific tag value
            let tagValIdx = meta.tags[this.state.deleteTagName].list.indexOf(
                this.state.deleteTagValue
            );
            meta.tags[this.state.deleteTagName].list.splice(tagValIdx, 1);
        } else {
            //delete entire tag
            delete meta.tags[this.state.deleteTagName];
        }
        let successMessage = this.state.deleteTagValue
            ? `Successfully deleted ${this.state.deleteTagValue} from tag ${this.state.deleteTagName}`
            : `Successfully deleted tag ${this.state.deleteTagName}`;
        this.updateMeta(meta, csrf, successMessage, true);
    }

    metaObject(collectionDetails, category) {
        if (category === 'domain') {
            return {
                description: collectionDetails.description,
                applicationId: collectionDetails.applicationId,
                tokenExpiryMins: collectionDetails.tokenExpiryMins,
                tagCertExpiryMins: collectionDetails.tagCertExpiryMins,
                roleCertExpiryMins: collectionDetails.roleCertExpiryMins,
                signAlgorithm: collectionDetails.signAlgorithm,
                memberExpiryDays: collectionDetails.memberExpiryDays,
                tagExpiryDays: collectionDetails.tagExpiryDays,
                groupExpiryDays: collectionDetails.groupExpiryDays,
                tags: collectionDetails.tags,
            };
        } else if (category === 'role') {
            return {
                selfServe: collectionDetails.selfServe,
                certExpiryMins: collectionDetails.certExpiryMins,
                reviewEnabled: collectionDetails.reviewEnabled,
                notifyRoles: collectionDetails.notifyRoles,
                serviceExpiryDays: collectionDetails.serviceExpiryDays,
                memberReviewDays: collectionDetails.memberReviewDays,
                serviceReviewDays: collectionDetails.serviceReviewDays,
                userAuthorityExpiration:
                    collectionDetails.userAuthorityExpiration,
                userAuthorityFilter: collectionDetails.userAuthorityFilter,
                memberExpiryDays: collectionDetails.memberExpiryDays,
                tokenExpiryMins: collectionDetails.tokenExpiryMins,
                signAlgorithm: collectionDetails.signAlgorithm,
                groupExpiryDays: collectionDetails.groupExpiryDays,
                tags: collectionDetails.tags,
            };
        } else if (category === 'group') {
            return {
                selfServe: collectionDetails.selfServe,
                reviewEnabled: collectionDetails.reviewEnabled,
                notifyRoles: collectionDetails.notifyRoles,
                serviceExpiryDays: collectionDetails.serviceExpiryDays,
                userAuthorityExpiration:
                    collectionDetails.userAuthorityExpiration,
                userAuthorityFilter: collectionDetails.userAuthorityFilter,
                memberExpiryDays: collectionDetails.memberExpiryDays,
                tags: collectionDetails.tags,
            };
        }
        // For Service and Policy just return the collection because we don't build a new metaData object.
        return collectionDetails;
    }

    updateMeta(meta, csrf, successMessage, showSuccess = true) {
        let auditRef =
            'Updated ' +
            this.props.category +
            ' ' +
            this.props.collectionName +
            ' Meta using Athenz UI';
        this.props
            .putMeta(
                this.props.domain,
                this.props.collectionName,
                meta,
                auditRef,
                csrf,
                this.state.category
            )
            .then(() => this.reloadTags(successMessage, showSuccess))
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    reloadTags(successMessage, showSuccess = true) {
        // if (this.state.category === 'domain') {
        this.updateStateAfterReload(
            this.props.collectionDetails,
            successMessage,
            showSuccess
        );
    }

    updateStateAfterReload(data, successMessage, showSuccess = true) {
        this.setState({
            tags: data.tags || {},
            showSuccess,
            successMessage,
            showDelete: false,
            showDeleteTagValue: false,
            showAddTag: false,
            editMode: false,
            editedTagKey: '',
            editedTagValues: [],
            errorMessage: null,
            deleteTagName: null,
            deleteTagValue: null,
        });
        // this is to close the success alert
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                    successMessage: '',
                }),
            MODAL_TIME_OUT
        );
    }
    closeModal() {
        this.setState({
            successMessage: '',
            showSuccess: false,
        });
    }
    render() {
        const left = 'left';
        const center = 'center';
        let rows = '';
        const clonedTags = AppUtils.deepClone(this.props.tags || {});
        let categoryObject =
            this.state.category !== 'domain'
                ? this.props.category === 'policy'
                    ? this.props.collectionName +
                      ':' +
                      this.props.collectionDetails?.version
                    : this.props.collectionName
                : this.props.domain;

        rows = Object.entries(clonedTags).map((item, i) => {
            const tagKey = item[0];
            const tagValues = item[1];
            let color = '';
            if (i % 2 === 0) {
                color = colors.row;
            }
            let toReturn = [];
            const updatedTagKey = this.state.successMessage === tagKey;
            toReturn.push(
                <TagRow
                    key={tagKey}
                    tagKey={tagKey}
                    tagValues={tagValues}
                    color={color}
                    _csrf={this.props._csrf}
                    onClickDeleteTag={() => this.onClickDeleteTag(tagKey)}
                    onClickDeleteTagValue={this.onClickDeleteTagValue}
                    onClickEditTag={this.onClickEditTag}
                    updatedTagKey={updatedTagKey}
                />
            );
            return toReturn;
        });
        let addTag = this.state.showAddTag ? (
            <AddTag
                showAddTag={this.state.showAddTag}
                editMode={this.state.editMode}
                onCancel={this.closeAddTag}
                resource={categoryObject}
                _csrf={this.props._csrf}
                addNewTag={this.addNewTag}
                editedTagKey={this.state.editedTagKey}
                editedTagValues={this.state.editedTagValues}
                errorMessage={this.state.errorMessage}
                validateTagExist={this.validateTagExist}
            />
        ) : (
            ''
        );
        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading tags data'} />
        ) : (
            <TagsSectionDiv data-testid='tag-list'>
                <AddContainerDiv>
                    <div>
                        <Button secondary onClick={this.openAddTag}>
                            Add Tag
                        </Button>
                        {addTag}
                    </div>
                </AddContainerDiv>
                {Object.keys(this.state.tags).length > 0 ? (
                    <TagTable>
                        <thead>
                            <tr>
                                <TableHeadStyled align={left}>
                                    TAG NAME
                                </TableHeadStyled>
                                <TableHeadStyled align={left}>
                                    TAG VALUES
                                </TableHeadStyled>
                                <TableHeadStyled align={center}>
                                    EDIT
                                </TableHeadStyled>
                                <TableHeadStyled align={center}>
                                    DELETE
                                </TableHeadStyled>
                            </tr>
                        </thead>
                        <tbody>{rows}</tbody>
                    </TagTable>
                ) : (
                    'Click on Add Tag to create a new tag'
                )}
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal}
                        type='success'
                    />
                ) : null}
                {this.state.showDelete ? (
                    <DeleteModal
                        name={this.state.deleteTagName}
                        isOpen={this.state.showDelete}
                        cancel={this.onCancelDeleteTag}
                        submit={this.onSubmitDeleteTag}
                        errorMessage={this.state.errorMessage}
                        message={
                            'Are you sure you want to permanently delete the Tag '
                        }
                    />
                ) : null}
                {this.state.showDeleteTagValue ? (
                    <DeleteModal
                        name={this.state.deleteTagValue}
                        isOpen={this.state.showDeleteTagValue}
                        cancel={this.onCancelDeleteTagValue}
                        submit={this.onSubmitDeleteTag}
                        errorMessage={this.state.errorMessage}
                        message={`Are you sure you want to permanently delete the Tag Value `}
                    />
                ) : null}
            </TagsSectionDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    putMeta: (domain, collectionName, detail, auditRef, _csrf, category) =>
        dispatch(
            updateTags(
                domain,
                collectionName,
                detail,
                auditRef,
                _csrf,
                category
            )
        ),
});

export default connect(mapStateToProps, mapDispatchToProps)(TagList);
