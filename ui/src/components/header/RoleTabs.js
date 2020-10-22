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
import TabGroup from '../denali/TabGroup';
import { Router } from '../../routes';

export default class RoleTabs extends React.Component {
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
            label: 'Policies',
            name: 'policies',
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
                this.props.api
                    .getStatus()
                    .then(function() {
                        Router.pushRoute('members', {
                            domain: domain,
                            role: role,
                        });
                    })
                    .catch((err) => {
                        if (err.statusCode === 0) {
                            window.location.reload();
                        }
                    });
                break;
            case 'review':
                this.props.api
                    .getStatus()
                    .then(function() {
                        Router.pushRoute('review', {
                            domain: domain,
                            role: role,
                        });
                    })
                    .catch((err) => {
                        if (err.statusCode === 0) {
                            window.location.reload();
                        }
                    });
                break;
            case 'policies':
                this.props.api
                    .getStatus()
                    .then(function() {
                        Router.pushRoute('role-policy', {
                            domain: domain,
                            role: role,
                        });
                    })
                    .catch((err) => {
                        if (err.statusCode === 0) {
                            window.location.reload();
                        }
                    });
                break;
            case 'settings':
                this.props.api
                    .getStatus()
                    .then(function() {
                        Router.pushRoute('settings', {
                            domain: domain,
                            role: role,
                        });
                    })
                    .catch((err) => {
                        if (err.statusCode === 0) {
                            window.location.reload();
                        }
                    });
                break;
            case 'history':
                this.props.api
                    .getStatus()
                    .then(function() {
                        Router.pushRoute('role-history', {
                            domain: domain,
                            role: role,
                        });
                    })
                    .catch((err) => {
                        if (err.statusCode === 0) {
                            window.location.reload();
                        }
                    });
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
