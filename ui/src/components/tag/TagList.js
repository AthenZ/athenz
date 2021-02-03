/*
 * Copyright 2021 Verizon Media
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
    font-size: 0.8rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;

export default class TagList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.onCancelDeleteTag = this.onCancelDeleteTag.bind(this);
        this.onCancelDeleteTagValue = this.onCancelDeleteTagValue.bind(this);
        this.reloadTags = this.reloadTags.bind(this);
        this.updateStateAfterReload = this.updateStateAfterReload.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.onSubmitDeleteTag = this.onSubmitDeleteTag.bind(this);
        this.openAddTag = this.openAddTag.bind(this);
        this.closeAddTag = this.closeAddTag.bind(this);
        this.addNewTag = this.addNewTag.bind(this);
        this.validateTagExist = this.validateTagExist.bind(this);
        this.domainMetaObject = this.domainMetaObject.bind(this);
        this.roleMetaObject = this.roleMetaObject.bind(this);
        this.updateMetaOnDelete = this.updateMetaOnDelete.bind(this);

        this.state = {
            category: props.category,
            tags: props.tags || [],
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
        return this.state.tags[tagName] != null;
    }

    addNewTag(tagKey, tagValues) {
        const csrf = this.props._csrf;
        if (this.state.category === 'domain') {
            this.api
                .getDomain(this.props.domain)
                .then((domain) => {
                    let domainMeta = this.domainMetaObject(domain);
                    if (!domainMeta.tags) {
                        domainMeta.tags = {};
                    }
                    domainMeta.tags[tagKey] = {};
                    domainMeta.tags[tagKey].list = tagValues;
                    let successMessage = this.state.editMode
                        ? `Successfully edited tag ${tagKey}`
                        : `Successfully added tag ${tagKey}`;
                    this.updateMeta(domainMeta, csrf, successMessage);
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        } else if (this.state.category === 'role') {
            this.api
                .getRole(this.props.domain, this.props.role)
                .then((role) => {
                    let roleMeta = this.roleMetaObject(role);
                    if (!roleMeta.tags) {
                        roleMeta.tags = {};
                    }
                    roleMeta.tags[tagKey] = {};
                    roleMeta.tags[tagKey].list = tagValues;
                    let successMessage = this.state.editMode
                        ? `Successfully edited tag ${tagKey}`
                        : `Successfully added tag ${tagKey}`;
                    this.updateMeta(roleMeta, csrf, successMessage);
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        }
    }

    onSubmitDeleteTag() {
        const csrf = this.props._csrf;
        if (this.state.category === 'domain') {
            this.api
                .getDomain(this.props.domain)
                .then((domain) => {
                    let domainMeta = this.domainMetaObject(domain);
                    this.updateMetaOnDelete(domainMeta, csrf);
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        } else if (this.state.category === 'role') {
            this.api
                .getRole(this.props.domain, this.props.role)
                .then((role) => {
                    let roleMeta = this.roleMetaObject(role);
                    this.updateMetaOnDelete(roleMeta, csrf);
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        }
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
        this.updateMeta(meta, csrf, successMessage);
    }

    domainMetaObject(domain) {
        return {
            description: domain.description,
            applicationId: domain.applicationId,
            tokenExpiryMins: domain.tokenExpiryMins,
            tagCertExpiryMins: domain.tagCertExpiryMins,
            roleCertExpiryMins: domain.roleCertExpiryMins,
            signAlgorithm: domain.signAlgorithm,
            memberExpiryDays: domain.memberExpiryDays,
            tagExpiryDays: domain.tagExpiryDays,
            groupExpiryDays: domain.groupExpiryDays,
            tags: domain.tags,
        };
    }

    roleMetaObject(role) {
        return {
            selfServe: role.selfServe,
            certExpiryMins: role.certExpiryMins,
            reviewEnabled: role.reviewEnabled,
            notifyRoles: role.notifyRoles,
            serviceExpiryDays: role.serviceExpiryDays,
            memberReviewDays: role.memberReviewDays,
            serviceReviewDays: role.serviceReviewDays,
            userAuthorityExpiration: role.userAuthorityExpiration,
            userAuthorityFilter: role.userAuthorityFilter,
            memberExpiryDays: role.memberExpiryDays,
            tokenExpiryMins: role.tokenExpiryMins,
            signAlgorithm: role.signAlgorithm,
            groupExpiryDays: role.groupExpiryDays,
            tags: role.tags,
        };
    }

    updateMeta(meta, csrf, successMessage) {
        this.api
            .putMeta(
                this.props.domain,
                this.state.category === 'domain'
                    ? this.props.domain
                    : this.props.role,
                meta,
                'Updated ' + this.props.domain + ' Meta using Athenz UI',
                csrf,
                this.state.category
            )
            .then(() => {
                this.reloadTags(successMessage, true);
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    reloadTags(successMessage) {
        if (this.state.category === 'domain') {
            this.props.api
                .getDomain(this.props.domain)
                .then((data) => {
                    this.updateStateAfterReload(data, successMessage);
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        } else if (this.state.category === 'role') {
            this.props.api
                .getRole(this.props.domain, this.props.role)
                .then((data) => {
                    this.updateStateAfterReload(data, successMessage);
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        }
    }

    updateStateAfterReload(data, successMessage) {
        this.setState({
            tags: data.tags,
            showSuccess: true,
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
        let addNewTag = this.addNewTag.bind(this);
        let validateTagExist = this.validateTagExist.bind(this);
        const left = 'left';
        const center = 'center';
        let rows = '';
        if (this.state.tags) {
            const clonedTags = JSON.parse(JSON.stringify(this.state.tags));
            rows = Object.entries(clonedTags).map((item, i) => {
                const tagKey = item[0];
                const tagValues = item[1];
                let onClickDeleteTag = this.onClickDeleteTag.bind(this, tagKey);
                let onClickDeleteTagValue = this.onClickDeleteTagValue.bind(
                    this
                );
                let onClickEditTag = this.onClickEditTag.bind(this);
                let color = '';
                if (i % 2 === 0) {
                    color = colors.row;
                }
                let toReturn = [];
                toReturn.push(
                    <TagRow
                        key={tagKey}
                        tagKey={tagKey}
                        tagValues={tagValues}
                        color={color}
                        api={this.api}
                        _csrf={this.props._csrf}
                        onClickDeleteTag={onClickDeleteTag}
                        onClickDeleteTagValue={onClickDeleteTagValue}
                        onClickEditTag={onClickEditTag}
                    />
                );
                return toReturn;
            });
        }
        let addTag = this.state.showAddTag ? (
            <AddTag
                showAddTag={this.state.showAddTag}
                editMode={this.state.editMode}
                onCancel={this.closeAddTag}
                onSubmit={this.reloadTags}
                resource={
                    this.state.category === 'domain'
                        ? this.props.domain
                        : this.props.role
                }
                api={this.api}
                _csrf={this.props._csrf}
                addNewTag={addNewTag}
                editedTagKey={this.state.editedTagKey}
                editedTagValues={this.state.editedTagValues}
                errorMessage={this.state.errorMessage}
                validateTagExist={validateTagExist}
            />
        ) : (
            ''
        );
        return (
            <TagsSectionDiv data-testid='tag-list'>
                <AddContainerDiv>
                    <div>
                        <Button secondary onClick={this.openAddTag}>
                            Add Tag
                        </Button>
                        {addTag}
                    </div>
                </AddContainerDiv>
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
