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
import API from '../../../api';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import TagRow from '../../../components/tag/TagRow';
import TagList from '../../../components/tag/TagList';

describe('TagList', () => {
    it('should render', async () => {
        const { getByTestId } = render(<TagList />);
        const tagList = getByTestId('tag-list');
        expect(tagList).toMatchSnapshot();
    });

    it('should display delete tag', async () => {
        let tags = {
            'tag-key': {
                list: ['tag-val1', 'tag-val2'],
            },
        };

        const { getByTestId } = render(
            <TagList domain={'domain'} tags={tags} category={'domain'} />
        );
        const tagList = getByTestId('tag-list');
        expect(tagList).toMatchSnapshot();

        fireEvent.click(screen.getByTitle('trash'));
        await waitFor(() => screen.getByText('This deletion is permanent'));
        expect(
            screen.getByText('This deletion is permanent')
        ).toBeInTheDocument();

        await waitFor(() =>
            screen.getByText(
                'Are you sure you want to permanently delete the Tag',
                { exact: false }
            )
        );
        expect(
            screen.getByText(
                'Are you sure you want to permanently delete the Tag',
                { exact: false }
            )
        ).toBeInTheDocument();

        // close delete tag
        fireEvent.click(screen.getByText('Cancel'));
    });

    it('should display delete tag value', async () => {
        let tags = {
            'tag-key': {
                list: ['tag-val1', 'tag-val2'],
            },
        };

        const { getByTestId } = render(
            <TagList domain={'domain'} tags={tags} category={'domain'} />
        );
        const tagList = getByTestId('tag-list');
        expect(tagList).toMatchSnapshot();

        // delete first value
        fireEvent.click(screen.getAllByText('x')[0]);

        await waitFor(() => screen.getByText('This deletion is permanent'));
        expect(
            screen.getByText('This deletion is permanent')
        ).toBeInTheDocument();

        await waitFor(() =>
            screen.getByText(
                'Are you sure you want to permanently delete the Tag Value',
                { exact: false }
            )
        );
        expect(
            screen.getByText(
                'Are you sure you want to permanently delete the Tag Value',
                { exact: false }
            )
        ).toBeInTheDocument();

        // close delete tag
        fireEvent.click(screen.getByText('Cancel'));
    });

    it('should display delete tag single value', async () => {
        let tags = {
            'tag-key': {
                list: ['tag-val1'],
            },
        };

        const { getByTestId } = render(
            <TagList domain={'domain'} tags={tags} category={'domain'} />
        );
        const tagList = getByTestId('tag-list');
        expect(tagList).toMatchSnapshot();

        // delete first value
        fireEvent.click(screen.getAllByText('x')[0]);

        await waitFor(() => screen.getByText('This deletion is permanent'));
        expect(
            screen.getByText('This deletion is permanent')
        ).toBeInTheDocument();

        // close delete tag
        fireEvent.click(screen.getByText('Cancel'));
    });

    it('should display add tag', async () => {
        const { getByTestId } = render(
            <TagList domain={'domain'} category={'domain'} />
        );
        const tagList = getByTestId('tag-list');
        expect(tagList).toMatchSnapshot();

        // open add tag
        fireEvent.click(screen.getByText('Add Tag'));
        await waitFor(() => screen.getByText('Add Tag to domain'));
        expect(screen.getByText('Add Tag to domain')).toBeInTheDocument();

        // close edit tag
        fireEvent.click(screen.getAllByText('x')[0]);
    });

    it('should display edit tag', async () => {
        let tags = {
            'tag-key': {
                list: ['tag-val1', 'tag-val2'],
            },
        };

        const { getByTestId } = render(
            <TagList domain={'domain'} tags={tags} category={'domain'} />
        );
        const tagList = getByTestId('tag-list');
        expect(tagList).toMatchSnapshot();

        // open edit tag
        fireEvent.click(screen.getByTitle('edit'));
        await waitFor(() => screen.getByText('Edit tag-key Tag'));
        expect(screen.getByText('Edit tag-key Tag')).toBeInTheDocument();

        // close edit tag
        fireEvent.click(screen.getAllByText('x')[0]);
    });

    it('should add new tag', async () => {
        let emptyObj = {}; // no tags
        let toReturnGetDomain = {
            tags: {
                'tag-name': {
                    list: ['first', 'second'],
                },
            },
        };

        const api = {
            getDomain: jest
                .fn()
                .mockReturnValueOnce(
                    new Promise((resolve, reject) => {
                        resolve(emptyObj);
                    })
                )
                .mockReturnValueOnce(
                    new Promise((resolve, reject) => {
                        resolve(toReturnGetDomain);
                    })
                ),
            putMeta: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(true);
                })
            ),
        };

        let tags = {
            'tag-exist': {
                list: ['v1', 'v2'],
            },
        };

        const { getByTestId } = render(
            <TagList
                domain={'domain'}
                category={'domain'}
                api={api}
                tags={tags}
                domainObj={toReturnGetDomain}
            />
        );
        const tagList = getByTestId('tag-list');
        expect(tagList).toMatchSnapshot();

        // open add tag
        fireEvent.click(screen.getByText('Add Tag'));
        await waitFor(() => screen.getByText('Add Tag to domain'));
        expect(screen.getByText('Add Tag to domain')).toBeInTheDocument();

        // add tag name
        fireEvent.change(screen.getByPlaceholderText('Enter New Tag Name'), {
            target: { value: 'tag-name' },
        });

        // add tag values
        fireEvent.change(screen.getByPlaceholderText('Enter New Tag Value'), {
            target: { value: 'first,second' },
        });
        // click add button
        fireEvent.click(screen.getByText('Add'));
        expect(screen.getByText('first')).toBeInTheDocument();
        expect(screen.getByText('second')).toBeInTheDocument();

        // click Submit button
        fireEvent.click(screen.getByText('Submit'));
    });

    it('should delete tag', async () => {
        let toReturnGetDomain = {
            tags: {
                'tag-name': {
                    list: ['first', 'second'],
                },
            },
        };

        const api = {
            getDomain: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(toReturnGetDomain);
                })
            ),
            putMeta: jest.fn().mockResolvedValue(true),
        };

        let tags = {
            'tag-name': {
                list: ['first', 'second'],
            },
        };

        const { getByTestId } = render(
            <TagList
                domain={'domain'}
                tags={tags}
                api={api}
                category={'domain'}
                domainObj={toReturnGetDomain}
            />
        );
        const tagList = getByTestId('tag-list');
        expect(tagList).toMatchSnapshot();

        fireEvent.click(screen.getByTitle('trash'));
        await waitFor(() => screen.getByText('This deletion is permanent'));
        expect(
            screen.getByText('This deletion is permanent')
        ).toBeInTheDocument();

        // delete the tag
        fireEvent.click(screen.getByText('Delete'));
    });

    it('should add new role tag', async () => {
        let emptyObj = {}; // no tags
        let toReturnGetRole = {
            tags: {
                'tag-name': {
                    list: ['first', 'second'],
                },
            },
        };

        const api = {
            getRole: jest
                .fn()
                .mockReturnValueOnce(
                    new Promise((resolve, reject) => {
                        resolve(emptyObj);
                    })
                )
                .mockReturnValueOnce(
                    new Promise((resolve, reject) => {
                        resolve(toReturnGetRole);
                    })
                ),
            putMeta: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(true);
                })
            ),
        };

        let tags = {
            'tag-exist': {
                list: ['v1', 'v2'],
            },
        };

        const { getByTestId } = render(
            <TagList
                domain={'domain'}
                role={'role'}
                category={'role'}
                api={api}
                tags={tags}
                roleObj={toReturnGetRole}
            />
        );
        const tagList = getByTestId('tag-list');
        expect(tagList).toMatchSnapshot();

        // open add tag
        fireEvent.click(screen.getByText('Add Tag'));
        await waitFor(() => screen.getByText('Add Tag to role'));
        expect(screen.getByText('Add Tag to role')).toBeInTheDocument();

        // add tag name
        fireEvent.change(screen.getByPlaceholderText('Enter New Tag Name'), {
            target: { value: 'tag-name' },
        });

        // add tag values
        fireEvent.change(screen.getByPlaceholderText('Enter New Tag Value'), {
            target: { value: 'first,second' },
        });
        // click add button
        fireEvent.click(screen.getByText('Add'));
        expect(screen.getByText('first')).toBeInTheDocument();
        expect(screen.getByText('second')).toBeInTheDocument();

        // click Submit button
        fireEvent.click(screen.getByText('Submit'));
    });

    it('should delete role tag', async () => {
        let toReturnGetRole = {
            tags: {
                'tag-name': {
                    list: ['first', 'second'],
                },
            },
        };

        const api = {
            getRole: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(toReturnGetRole);
                })
            ),
            putMeta: jest.fn().mockResolvedValue(true),
        };

        let tags = {
            'tag-name': {
                list: ['first', 'second'],
            },
        };

        const { getByTestId } = render(
            <TagList
                domain={'domain'}
                tags={tags}
                api={api}
                role={'role'}
                category={'role'}
                roleObj={toReturnGetRole}
            />
        );
        const tagList = getByTestId('tag-list');
        expect(tagList).toMatchSnapshot();

        fireEvent.click(screen.getByTitle('trash'));
        await waitFor(() => screen.getByText('This deletion is permanent'));
        expect(
            screen.getByText('This deletion is permanent')
        ).toBeInTheDocument();

        // delete the tag
        fireEvent.click(screen.getByText('Delete'));
    });
});
