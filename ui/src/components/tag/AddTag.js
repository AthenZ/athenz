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
import AddModal from '../modal/AddModal';
import AddTagForm from './AddTagForm';
import AppUtils from '../utils/AppUtils';

export default class AddTag extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        AppUtils.bindClassMethods(this);
        if (props.editedTagKey && props.editedTagValues) {
            this.state = {
                editMode: true,
                showModal: !!this.props.showAddTag,
                tagName: props.editedTagKey,
                tagValues: props.editedTagValues,
                newTagValue: '',
            };
        } else {
            this.state = {
                showModal: !!this.props.showAddTag,
                tagName: '',
                tagValues: [],
                newTagValue: '',
            };
        }
    }

    onSubmit() {
        if (!this.state.tagName || this.state.tagName === '') {
            this.setState({
                errorMessage: 'Tag name is required.',
            });
            return;
        }
        if (
            !this.props.editMode &&
            this.props.validateTagExist(this.state.tagName)
        ) {
            this.setState({
                errorMessage: 'Tag already exist.',
            });
            return;
        }

        if (
            !this.state.newTagValue &&
            (!this.state.tagValues || this.state.tagValues.length === 0)
        ) {
            this.setState({
                errorMessage: 'Tag value is required.',
            });
            return;
        }
        let notAddedTag = this.state.newTagValue.trim();
        if (notAddedTag) {
            let tagValues = AppUtils.deepClone(this.state.tagValues);
            tagValues.push(notAddedTag);
            this.setState(
                {
                    tagValues: tagValues,
                },
                () =>
                    this.props.addNewTag(
                        this.state.tagName,
                        this.state.tagValues
                    )
            );
        } else {
            this.props.addNewTag(this.state.tagName, this.state.tagValues);
        }
    }

    onUpdate(tagKey, newTagValue, tagValues) {
        this.setState({
            tagName: tagKey,
            newTagValue: newTagValue,
            tagValues: tagValues,
        });
    }

    render() {
        const title = this.props.editMode
            ? 'Edit ' + this.state.tagName + ' Tag'
            : 'Add Tag to ' + this.props.resource;
        return (
            <AddModal
                isOpen={this.state.showModal}
                cancel={this.props.onCancel}
                submit={this.onSubmit}
                title={title}
                errorMessage={
                    this.props.errorMessage || this.state.errorMessage
                }
                sections={
                    <AddTagForm
                        onUpdate={this.onUpdate}
                        editedTagKey={this.state.tagName}
                        editedTagValues={this.state.tagValues}
                        editMode={this.state.editMode}
                    />
                }
            />
        );
    }
}
