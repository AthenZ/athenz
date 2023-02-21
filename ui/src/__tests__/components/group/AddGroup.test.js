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
import {
    render,
    fireEvent,
    waitFor,
    screen,
    cleanup,
    getByTestId,
} from '@testing-library/react';
import AddGroup from '../../../components/group/AddGroup';
import API from '../../../api';
import {
    ADD_GROUP_AUDIT_ENABLED_TOOLTIP,
    GROUP_MEMBER_PLACEHOLDER,
} from '../../../components/constants/constants';
import {
    buildDomainDataForState,
    buildGroupsForState,
    getStateWithDomainData,
    getStateWithGroups,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';
import { singleApiGroup } from '../../redux/config/group.test';

describe('AddGroup', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
        cleanup();
    });

    it('should render', () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const { getByTestId } = renderWithRedux(
            <AddGroup domain={domain} showAddGroup={true} onCancel={onClose} />,
            getStateWithDomainData(domainData)
        );
        const addGroupForm = getByTestId('add-group');
        expect(addGroupForm).toMatchSnapshot();
    });

    it('should throw error for group name 1', async () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const onSubmit = jest.fn();
        const _csrf = '_csrf';

        const { getByText } = renderWithRedux(
            <AddGroup
                _csrf={_csrf}
                onSubmit={onSubmit}
                domain={domain}
                showAddGroup={true}
                onCancel={onClose}
            />,
            getStateWithDomainData(domainData)
        );
        expect(
            screen.getByPlaceholderText('Enter New Group Name')
        ).toBeInTheDocument();
        fireEvent.change(screen.getByPlaceholderText('Enter New Group Name'), {
            target: { value: 'testgroup:test' },
        });
        fireEvent.change(
            screen.getByPlaceholderText('Enter justification here'),
            {
                target: { value: 'justification' },
            }
        );
        const button = getByText('Submit');
        fireEvent.click(button);
        await waitFor(() => {
            expect(
                screen.getByText("Group name doesn't match regex:", {
                    exact: false,
                })
            ).toBeInTheDocument();
        });
    });

    it('should throw error for group name 2', async () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const onSubmit = jest.fn();
        const _csrf = '_csrf';

        const { getByText } = renderWithRedux(
            <AddGroup
                _csrf={_csrf}
                onSubmit={onSubmit}
                domain={domain}
                showAddGroup={true}
                onCancel={onClose}
            />,
            getStateWithDomainData(domainData)
        );
        expect(
            screen.getByPlaceholderText('Enter New Group Name')
        ).toBeInTheDocument();

        fireEvent.change(
            screen.getByPlaceholderText('Enter justification here'),
            {
                target: { value: 'justification' },
            }
        );
        fireEvent.change(screen.getByPlaceholderText('Enter New Group Name'), {
            target: { value: 'group(123)' },
        });
        const button = getByText('Submit');
        fireEvent.click(button);
        await waitFor(() => {
            expect(
                screen.getByText("Group name doesn't match regex:", {
                    exact: false,
                })
            ).toBeInTheDocument();
        });
    });

    it('should throw error for group name 3', async () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const onSubmit = jest.fn();
        const _csrf = '_csrf';

        const { getByText } = renderWithRedux(
            <AddGroup
                _csrf={_csrf}
                onSubmit={onSubmit}
                domain={domain}
                showAddGroup={true}
                onCancel={onClose}
            />,
            getStateWithDomainData(domainData)
        );
        expect(
            screen.getByPlaceholderText('Enter New Group Name')
        ).toBeInTheDocument();

        fireEvent.change(
            screen.getByPlaceholderText('Enter justification here'),
            {
                target: { value: 'justification' },
            }
        );
        fireEvent.change(screen.getByPlaceholderText('Enter New Group Name'), {
            target: { value: 'group/123' },
        });
        const button = getByText('Submit');
        fireEvent.click(button);
        await waitFor(() => {
            expect(
                screen.getByText("Group name doesn't match regex:", {
                    exact: false,
                })
            ).toBeInTheDocument();
        });
    });

    it('should not throw error for group name', async () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const onSubmit = jest.fn();
        const _csrf = '_csrf';
        const api = {
            addGroup: jest.fn(() => Promise.resolve(singleApiGroup)),
        };
        MockApi.setMockApi(api);
        const groups = buildGroupsForState({}, domain);
        const { getByText } = renderWithRedux(
            <AddGroup
                _csrf={_csrf}
                onSubmit={onSubmit}
                domain={domain}
                showAddGroup={true}
                onCancel={onClose}
                groupNames={'group1'}
            />,
            getStateWithGroups(groups, { domainData: domainData })
        );
        expect(
            screen.getByPlaceholderText('Enter New Group Name')
        ).toBeInTheDocument();

        fireEvent.change(
            screen.getByPlaceholderText('Enter justification here'),
            {
                target: { value: 'justification' },
            }
        );
        const button = getByText('Submit');
        fireEvent.change(screen.getByPlaceholderText('Enter New Group Name'), {
            target: { value: 'group.test' },
        });
        fireEvent.click(button);
        await waitFor(() => {
            expect(onSubmit.mock.calls.length).toBe(1);
        });
    });

    it('should throw error for group member name 1', async () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const onSubmit = jest.fn();
        const _csrf = '_csrf';

        const { getByText } = renderWithRedux(
            <AddGroup
                _csrf={_csrf}
                onSubmit={onSubmit}
                domain={domain}
                showAddGroup={true}
                onCancel={onClose}
            />,
            getStateWithDomainData(domainData)
        );
        expect(
            screen.getByPlaceholderText(GROUP_MEMBER_PLACEHOLDER)
        ).toBeInTheDocument();

        fireEvent.change(
            screen.getByPlaceholderText('Enter justification here'),
            {
                target: { value: 'justification' },
            }
        );
        fireEvent.change(
            screen.getByPlaceholderText(GROUP_MEMBER_PLACEHOLDER),
            {
                target: { value: 'home.test:group.test' },
            }
        );
        const button = getByText('Add');
        fireEvent.click(button);
        await waitFor(() => {
            expect(
                screen.getByText("Member name doesn't match regex: ", {
                    exact: false,
                })
            ).toBeInTheDocument();
        });
    });

    it('should throw error for group member name 2', async () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const onSubmit = jest.fn();
        const _csrf = '_csrf';

        const { getByText } = renderWithRedux(
            <AddGroup
                _csrf={_csrf}
                onSubmit={onSubmit}
                domain={domain}
                showAddGroup={true}
                onCancel={onClose}
            />,
            getStateWithDomainData(domainData)
        );
        expect(
            screen.getByPlaceholderText(GROUP_MEMBER_PLACEHOLDER)
        ).toBeInTheDocument();

        fireEvent.change(
            screen.getByPlaceholderText('Enter justification here'),
            {
                target: { value: 'justification' },
            }
        );
        fireEvent.change(
            screen.getByPlaceholderText(GROUP_MEMBER_PLACEHOLDER),
            {
                target: { value: 'user.test1.' },
            }
        );
        const button = getByText('Add');
        fireEvent.click(button);
        await waitFor(() => {
            expect(
                screen.getByText("Member name doesn't match regex: ", {
                    exact: false,
                })
            ).toBeInTheDocument();
        });
    });

    it('should throw error for group member name 3', async () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const onSubmit = jest.fn();
        const _csrf = '_csrf';

        const { getByText } = renderWithRedux(
            <AddGroup
                _csrf={_csrf}
                onSubmit={onSubmit}
                domain={domain}
                showAddGroup={true}
                onCancel={onClose}
            />,
            getStateWithDomainData(domainData)
        );
        expect(
            screen.getByPlaceholderText(GROUP_MEMBER_PLACEHOLDER)
        ).toBeInTheDocument();

        fireEvent.change(
            screen.getByPlaceholderText('Enter justification here'),
            {
                target: { value: 'justification' },
            }
        );
        fireEvent.change(
            screen.getByPlaceholderText(GROUP_MEMBER_PLACEHOLDER),
            {
                target: { value: 'unix.service.test/' },
            }
        );
        const button = getByText('Add');
        fireEvent.click(button);
        await waitFor(() => {
            expect(
                screen.getByText("Member name doesn't match regex: ", {
                    exact: false,
                })
            ).toBeInTheDocument();
        });
    });

    it('should not throw error for group member name', async () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const onSubmit = jest.fn();
        const _csrf = '_csrf';
        const api = {
            addGroup: jest.fn(() => Promise.resolve({ name: 'group.test' })),
        };
        const groups = buildGroupsForState({}, domain);
        MockApi.setMockApi(api);
        const { getByText } = renderWithRedux(
            <AddGroup
                _csrf={_csrf}
                onSubmit={onSubmit}
                domain={domain}
                showAddGroup={true}
                onCancel={onClose}
            />,
            getStateWithGroups(groups, { domainData: domainData })
        );
        expect(
            screen.getByPlaceholderText('Enter New Group Name')
        ).toBeInTheDocument();

        fireEvent.change(
            screen.getByPlaceholderText('Enter justification here'),
            {
                target: { value: 'justification' },
            }
        );
        const button = getByText('Submit');
        fireEvent.change(screen.getByPlaceholderText('Enter New Group Name'), {
            target: { value: 'group.test' },
        });
        fireEvent.change(
            screen.getByPlaceholderText(GROUP_MEMBER_PLACEHOLDER),
            {
                target: { value: 'user.test' },
            }
        );
        fireEvent.click(button);
        await waitFor(() => {
            expect(onSubmit.mock.calls.length).toBe(1);
        });
    });

    it('should have auditEnabled switch', async () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const onSubmit = jest.fn();
        const _csrf = '_csrf';

        const { getByText } = renderWithRedux(
            <AddGroup
                _csrf={_csrf}
                onSubmit={onSubmit}
                domain={domain}
                showAddGroup={true}
                onCancel={onClose}
            />,
            getStateWithDomainData(domainData)
        );

        expect(
            screen.getByTestId('auditEnabled-switch-input')
        ).toBeInTheDocument();

        expect(screen.getAllByTestId('auditEnabled-switch-input')).toHaveLength(
            1
        );

        fireEvent.click(screen.getByTestId('auditEnabled-switch-input'));

        await waitFor(() => {
            expect(
                screen.getAllByTitle(ADD_GROUP_AUDIT_ENABLED_TOOLTIP)
            ).toHaveLength(2);
        });
    });

    it('should have auditEnabled switch disabled after user is added', async () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const onSubmit = jest.fn();
        const _csrf = '_csrf';

        const { getByText } = renderWithRedux(
            <AddGroup
                _csrf={_csrf}
                onSubmit={onSubmit}
                domain={domain}
                showAddGroup={true}
                onCancel={onClose}
            />,
            getStateWithDomainData(domainData)
        );

        fireEvent.change(
            screen.getByPlaceholderText(GROUP_MEMBER_PLACEHOLDER),
            {
                target: { value: 'user.test' },
            }
        );

        const button = getByText('Add');
        fireEvent.click(button);

        await waitFor(() => {
            expect(
                screen.getByTestId('auditEnabled-switch-input')
            ).toBeDisabled();
        });
    });

    it('should open modal with auditEnabled switch', async () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const onSubmit = jest.fn();
        const _csrf = '_csrf';

        const { getByTestId } = renderWithRedux(
            <AddGroup
                _csrf={_csrf}
                onSubmit={onSubmit}
                domain={domain}
                showAddGroup={true}
                onCancel={onClose}
            />,
            getStateWithDomainData(domainData)
        );

        await waitFor(() => {
            expect(
                screen.queryByTestId('auditEnabled-switch-input')
            ).toBeEnabled();
        });
    });

    it('should open modal without auditEnabled switch', async () => {
        let domain = 'domain';
        const domainMetadata = {
            auditEnabled: false,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onClose = jest.fn();
        const onSubmit = jest.fn();
        const _csrf = '_csrf';

        const { getByTestId } = renderWithRedux(
            <AddGroup
                _csrf={_csrf}
                onSubmit={onSubmit}
                domain={domain}
                showAddGroup={true}
                onCancel={onClose}
            />,
            getStateWithDomainData(domainData)
        );

        const auditEnabledSwitch = screen.queryByText('Audit Enabled');
        expect(auditEnabledSwitch).toBeNull();
    });
});
