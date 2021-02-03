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
import AddModal from '../modal/AddModal';
import AddTagForm from './AddTagForm';

export default class AddTag extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.onSubmit = this.onSubmit.bind(this);

        if (props.editedTagKey && props.editedTagValues) {
            this.state = {
                showModal: !!this.props.showAddTag,
                tagName: props.editedTagKey,
                tagValues: props.editedTagValues,
            };
        } else {
            this.state = {
                showModal: !!this.props.showAddTag,
                tagName: '',
                tagValues: [],
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

        if (!this.state.tagValues || this.state.tagValues.length === 0) {
            this.setState({
                errorMessage: 'Tag value is required.',
            });
            return;
        }

        this.props.addNewTag(this.state.tagName, this.state.tagValues);
    }

    onUpdate(tagKey, tagValues) {
        this.state.tagName = tagKey;
        this.state.tagValues = tagValues;
    }

    render() {
        let onUpdate = this.onUpdate.bind(this);
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
                        api={this.api}
                        onUpdate={onUpdate}
                        editedTagKey={this.state.tagName}
                        editedTagValues={this.state.tagValues}
                    />
                }
            />
        );
    }
}
