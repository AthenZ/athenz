/*
 * Copyright 2020 Verizon Media
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
import SettingTable from './SettingTable';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';

const RolesSectionDiv = styled.div`
    margin: 20px;
`;

export default class SettingList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.onSubmit = this.onSubmit.bind(this);
        this.reloadCollection = this.reloadCollection.bind(this);
        this.state = {
            collectionDetails: props.collectionDetails,
            errorMessage: null,
        };
    }

    componentDidUpdate = (prevProps) => {
        if (
            prevProps.collection !== this.props.collection ||
            prevProps.domain !== this.props.domain ||
            prevProps.collectionDetails !== this.props.collectionDetails
        ) {
            this.setState({
                collectionDetails: this.props.collectionDetails,
            });
        }
    };

    onSubmit() {
        this.reloadCollection();
    }

    reloadCollection() {
        this.api
            .getCollection(
                this.props.domain,
                this.props.collection,
                this.props.category
            )
            .then((collection) => {
                this.setState({
                    collectionDetails: collection,
                    errorMessage: null,
                });
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        const { domain, collection } = this.props;

        return (
            <RolesSectionDiv data-testid='setting-list'>
                <SettingTable
                    domain={domain}
                    collection={collection}
                    collectionDetails={this.state.collectionDetails}
                    onSubmit={this.onSubmit}
                    api={this.api}
                    _csrf={this.props._csrf}
                    justificationRequired={this.props.isDomainAuditEnabled}
                    userProfileLink={this.props.userProfileLink}
                    category={this.props.category}
                />
            </RolesSectionDiv>
        );
    }
}
