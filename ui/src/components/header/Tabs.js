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
import TabGroup from '../denali/TabGroup';
import { withRouter } from 'next/router';
import { connect } from 'react-redux';
import { selectFeatureFlag } from '../../redux/selectors/domains';

class Tabs extends React.Component {
    constructor(props) {
        super(props);
        this.tabClicked = this.tabClicked.bind(this);
    }
    TABS = [
        {
            label: 'Roles',
            name: 'roles',
        },
        {
            label: 'Groups',
            name: 'groups',
        },
        {
            label: 'Services',
            name: 'services',
        },
        {
            label: 'Policies',
            name: 'policies',
        },
        {
            label: 'Tags',
            name: 'tags',
        },
        {
            label: 'Templates',
            name: 'templates',
        },
        {
            label: 'Settings',
            name: 'domain-settings',
        },
        {
            label: 'Visibility',
            name: 'visibility',
        },
        {
            label: 'History',
            name: 'history',
        },
    ];

    tabClicked(tab) {
        const { domain } = this.props;
        switch (tab.name) {
            case 'roles':
                this.props.router.push(
                    `/domain/${domain}/role`,
                    `/domain/${domain}/role`
                );
                break;
            case 'services':
                this.props.router.push(
                    `/domain/${domain}/service`,
                    `/domain/${domain}/service`
                );
                break;
            case 'groups':
                this.props.router.push(
                    `/domain/${domain}/group`,
                    `/domain/${domain}/group`
                );
                break;
            case 'policies':
                this.props.router.push(
                    `/domain/${domain}/policy`,
                    `/domain/${domain}/policy`
                );
                break;
            case 'history':
                this.props.router.push(
                    `/domain/${domain}/history`,
                    `/domain/${domain}/history`
                );
                break;
            case 'templates':
                this.props.router.push(
                    `/domain/${domain}/template`,
                    `/domain/${domain}/template`
                );
                break;
            case 'tags':
                this.props.router.push(
                    `/domain/${domain}/tags`,
                    `/domain/${domain}/tags`
                );
                break;
            case 'microsegmentation':
                this.props.router.push(
                    `/domain/${domain}/microsegmentation`,
                    `/domain/${domain}/microsegmentation`
                );
                break;
            case 'domain-settings':
                this.props.router.push(
                    `/domain/${domain}/domain-settings`,
                    `/domain/${domain}/domain-settings`
                );
                break;
            case 'visibility':
                this.props.router.push(
                    `/domain/${domain}/visibility`,
                    `/domain/${domain}/visibility`
                );
                break;
        }
    }

    render() {
        let microSeg = {
            label: 'Microsegmentation',
            name: 'microsegmentation',
        };

        if (this.props.featureFlag) {
            this.TABS.push(microSeg);
        }
        return (
            <TabGroup
                tabs={this.TABS}
                selectedName={this.props.selectedName}
                onClick={this.tabClicked}
                noanim
            />
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        featureFlag: selectFeatureFlag(state),
    };
};

export default connect(mapStateToProps)(withRouter(Tabs));
