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

class GroupTabs extends React.Component {
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
            label: 'Roles',
            name: 'roles',
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
        const { domain, group } = this.props;
        switch (tab.name) {
            case 'members':
                this.props.router.push(
                    `/domain/${domain}/group/${group}/members`,
                    `/domain/${domain}/group/${group}/members`
                );
                break;
            case 'review':
                this.props.router.push(
                    `/domain/${domain}/group/${group}/review`,
                    `/domain/${domain}/group/${group}/review`
                );
                break;
            case 'roles':
                this.props.router.push(
                    `/domain/${domain}/group/${group}/roles`,
                    `/domain/${domain}/group/${group}/roles`
                );
                break;
            case 'settings':
                this.props.router.push(
                    `/domain/${domain}/group/${group}/settings`,
                    `/domain/${domain}/group/${group}/settings`
                );
                break;
            case 'history':
                this.props.router.push(
                    `/domain/${domain}/group/${group}/history`,
                    `/domain/${domain}/group/${group}/history`
                );
                break;
            case 'tags':
                this.props.router.push(
                    `/domain/${domain}/group/${group}/tags`,
                    `/domain/${domain}/group/${group}/tags`
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
export default withRouter(GroupTabs);
