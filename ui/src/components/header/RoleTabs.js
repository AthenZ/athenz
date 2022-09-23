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

class RoleTabs extends React.Component {
    constructor(props) {
        super(props);
        this.tabClicked = this.tabClicked.bind(this);
    }
    TABS = [
        {
            label: 'Members',
            name: 'members',
        },
        {
            label: 'Review',
            name: 'review',
        },
        {
            label: 'Policy Rules',
            name: 'policies',
        },
        {
            label: 'Tags',
            name: 'tags',
        },
        {
            label: 'Settings',
            name: 'settings',
        },
        {
            label: 'History',
            name: 'history',
        },
    ];

    tabClicked(tab) {
        const { domain, role } = this.props;
        switch (tab.name) {
            case 'members':
                this.props.router.push(
                    `/domain/${domain}/role/${role}/members`,
                    `/domain/${domain}/role/${role}/members`
                );
                break;
            case 'review':
                this.props.router.push(
                    `/domain/${domain}/role/${role}/review`,
                    `/domain/${domain}/role/${role}/review`
                );
                break;
            case 'policies':
                this.props.router.push(
                    `/domain/${domain}/role/${role}/policy`,
                    `/domain/${domain}/role/${role}/policy`
                );
                break;
            case 'settings':
                this.props.router.push(
                    `/domain/${domain}/role/${role}/settings`,
                    `/domain/${domain}/role/${role}/settings`
                );
                break;
            case 'history':
                this.props.router.push(
                    `/domain/${domain}/role/${role}/history`,
                    `/domain/${domain}/role/${role}/history`
                );
                break;
            case 'tags':
                this.props.router.push(
                    `/domain/${domain}/role/${role}/tags`,
                    `/domain/${domain}/role/${role}/tags`
                );
                break;
        }
    }

    render() {
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
export default withRouter(RoleTabs);
