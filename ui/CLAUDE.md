# Athenz UI Project Overview and Coding Guidelines

## Project Overview

**Athenz UI** is a browser-based user interface for Athenz, an enterprise role-based access control (RBAC) system developed by Yahoo/Verizon Media.

### Basic Information
- **Name**: @athenz/ui
- **Version**: 0.4.0
- **License**: Apache-2.0
- **Description**: React-based UI for Athenz
- **Main Purpose**: Management and display of domains, roles, policies, services, etc.

### Technology Stack
- **Frontend**: React 18.2.0 + Next.js 14.2.26 (with SSR/SSG support)
- **State Management**: Redux + Redux Toolkit + Redux Thunk
- **Styling**: Emotion CSS-in-JS + Denali Design System
- **Server**: Express.js (with HTTPS support + custom authentication)
- **Testing**: Jest + React Testing Library + WebdriverIO
- **Build**: Next.js build system + TypeScript support

### Architecture Features
- **Modular Design**: Clear separation of UI, state, and business logic
- **Scalable State Management**: Domain-driven Redux architecture
- **Component Reusability**: Design system-based component library
- **Full-stack Integration**: Express server and Next.js frontend
- **Security Focus**: CSRF protection, secure session handling
- **Developer Experience**: Comprehensive testing, hot reload, debugging tools

---

## Language Guidelines

### String Literals and Comments
- ✅ **Code Comments**: Write all code comments in English
- ✅ **String Literals**: Use English for placeholder text, error messages, and constants
- ✅ **Variable Names**: Use descriptive English names for variables and functions
- ✅ **User-facing Text**: Keep user-facing text localized according to project requirements
- ✅ **Documentation**: Write technical documentation and inline JSDoc comments in English

#### Example:
```javascript
// Good: English comments and string literals
const ERROR_MESSAGES = {
    INVALID_DOMAIN: 'Invalid domain name provided',
    NETWORK_ERROR: 'Failed to connect to server',
};

/**
 * Validates the domain name format
 * @param {string} domainName - The domain name to validate
 * @returns {boolean} - True if valid, false otherwise
 */
const validateDomainName = (domainName) => {
    // Check if domain name matches required pattern
    if (!domainName || typeof domainName !== 'string') {
        throw new Error('Domain name must be a non-empty string');
    }
    return DOMAIN_PATTERN.test(domainName);
};
```

---

## Category-specific Coding Guidelines

### 1. 🏗️ Component Patterns

#### Basic Structure
```javascript
/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import React from 'react';
import PropTypes from 'prop-types';
import styled from '@emotion/styled';

class ComponentName extends React.Component {
    constructor(props) {
        super(props);
        this.state = {};
    }
    
    componentDidMount() {}
    componentDidUpdate() {}
    
    render() {
        return (
            <div data-testid='component-name'>
                {/* content */}
            </div>
        );
    }
}

ComponentName.propTypes = {
    /** Property description */
    propertyName: PropTypes.string.isRequired,
    /** Optional property */
    optionalProp: PropTypes.bool,
};

ComponentName.defaultProps = {
    optionalProp: false,
};

export default ComponentName;
```

#### Required Rules
- ✅ **License Header**: Include Apache License 2.0 in all files
- ✅ **Class Components**: Use React class components for stateful logic
- ✅ **PropTypes Definition**: Define detailed PropTypes for all components
- ✅ **Default Props**: Provide defaultProps for optional properties
- ✅ **Test ID**: Add `data-testid` attribute for testing
- ✅ **Default Export**: Use default export for main components

### 2. 🎨 Styling Patterns (Emotion CSS-in-JS)

#### Basic Patterns
```javascript
import styled from '@emotion/styled';
import { css, cx } from '@emotion/css';
import { colors } from '../denali/styles/colors';

// styled-components pattern
const StyledComponent = styled.div`
    background: ${colors.brand600};
    padding: 10px;
    font-family: ${(props) => props.theme.fonts.body};
    
    &:hover {
        background: ${colors.brand700};
    }
`;

// dynamic style pattern
const dynamicStyle = (props) => css`
    font-size: ${props.size === 'large' ? '18px' : '14px'};
    color: ${props.danger ? colors.red500 : colors.grey800};
    
    ${props.responsive && `
        @media (max-width: 768px) {
            font-size: 14px;
        }
    `}
`;
```

#### Styling Guidelines
- ✅ **Color Consistency**: Use color palette from `src/components/denali/styles/colors.js`
- ✅ **Responsive**: Follow design system breakpoints
- ✅ **Font Consistency**: Use standard font families from style constants
- ✅ **CSS Property Order**: Group related properties together
- ✅ **Template Literals**: Use template literals for multi-line CSS
- ✅ **styled-components Preference**: Prefer styled-components over inline styles

### 3. 🔄 Redux Patterns

#### Action Creators
```javascript
// Action constants
export const LOAD_ROLES = 'LOAD_ROLES';
export const LOADING_IN_PROCESS = 'LOADING_IN_PROCESS';
export const LOADING_SUCCESS = 'LOADING_SUCCESS';
export const LOADING_FAILED = 'LOADING_FAILED';

// Action creators
export const loadRoles = (roles, domainName, expiry) => ({
    type: LOAD_ROLES,
    payload: { roles, domainName, expiry },
});

export const loadingInProcess = (action) => ({
    type: LOADING_IN_PROCESS,
    payload: { name: action },
});
```

#### Reducer Patterns (Using Immer)
```javascript
import produce from 'immer';

export const roles = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_ROLES: {
            return produce(state, (draft) => {
                draft.roles = payload.roles;
                draft.domainName = payload.domainName;
                draft.expiry = payload.expiry;
            });
        }
        case DELETE_ROLE: {
            return produce(state, (draft) => {
                delete draft.roles[payload.roleName];
            });
        }
        default:
            return state;
    }
};
```

#### Thunk Patterns (Asynchronous Operations)
```javascript
export const getRoles = (domainName) => async (dispatch, getState) => {
    // Cache check
    if (isDataCached(getState(), domainName)) {
        dispatch(returnRoles());
        return;
    }
    
    try {
        dispatch(loadingInProcess('getRoles'));
        const data = await API().getRoles(domainName);
        
        // Data transformation and caching
        const transformedRoles = buildRolesMap(data);
        dispatch(loadRoles(transformedRoles, domainName, getExpiryTime()));
        dispatch(loadingSuccess('getRoles'));
    } catch (error) {
        dispatch(loadingFailed('getRoles', error));
        throw error;
    }
};
```

#### Selector Patterns
```javascript
// Basic selector
export const selectRoles = (state) => {
    return state.roles.roles ? mapToList(state.roles.roles) : [];
};

// Parameterized selector
export const selectRoleMembers = (state, domainName, roleName) => {
    const fullRoleName = getFullName(domainName, roleDelimiter, roleName);
    return state.roles?.roles?.[fullRoleName]?.roleMembers
        ? membersMapsToList(state.roles.roles[fullRoleName].roleMembers)
        : [];
};

// Selector for thunks
export const thunkSelectRoles = (state) => {
    return state.roles.roles ? state.roles.roles : {};
};
```

#### Redux Guidelines
- ✅ **Constant Naming**: Action types use SCREAMING_SNAKE_CASE
- ✅ **Immer Usage**: Use Immer's produce for immutable updates
- ✅ **Async Patterns**: Consistent use of async/await and try/catch
- ✅ **Loading States**: Manage loading states for all async operations
- ✅ **Data Caching**: Optimize API calls with expiration-based caching
- ✅ **Selector Usage**: Transform data in selectors, not components

### 4. 📄 Next.js Page Patterns

#### getServerSideProps Pattern
```javascript
export async function getServerSideProps(context) {
    let api = API(context.req);
    let reload = false;
    let error = null;
    let data = {};
    
    try {
        data = await api.getData();
    } catch (err) {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
    }
    
    return {
        props: {
            reload,
            error,
            userName: context.req.session.shortId,
            _csrf: data._csrf,
            nonce: context.req.headers.rid,
            // Page-specific data
            domainData: data.domainData || {},
        },
    };
}
```

#### Page Component Structure
```javascript
class PageComponent extends React.Component {
    constructor(props) {
        super(props);
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
    }
    
    componentDidMount() {
        const { dispatch, domainName } = this.props;
        Promise.all([
            dispatch(getRoles(domainName)),
            dispatch(getPolicies(domainName)),
        ]).catch((err) => {
            this.showError(RequestUtils.fetcherErrorCheckHelper(err));
        });
    }
    
    render() {
        // Reload handling
        if (this.props.reload) {
            window.location.reload();
            return <div />;
        }
        
        // Error handling
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }
        
        return (
            <CacheProvider value={this.cache}>
                <div>
                    {/* Page content */}
                </div>
            </CacheProvider>
        );
    }
}

// Redux connection
const mapStateToProps = (state, props) => ({
    ...state,
});

const mapDispatchToProps = (dispatch) => ({
    dispatch,
});

export default connect(mapStateToProps, mapDispatchToProps)(PageComponent);
```

#### Next.js Guidelines
- ✅ **Consistent Error Handling**: Use RequestUtils.errorCheckHelper
- ✅ **Standard Props Structure**: Include reload, error, userName
- ✅ **CSRF Token**: Provide CSRF token for forms
- ✅ **CSP Compliance**: Use nonce for CSP-compliant styling

### 5. 🧪 Testing Patterns

#### Component Testing
```javascript
import React from 'react';
import { render, fireEvent } from '@testing-library/react';
import ComponentName from '../ComponentName';

describe('ComponentName', () => {
    it('should render with default props', () => {
        const { getByTestId } = render(<ComponentName />);
        expect(getByTestId('component-name')).toMatchSnapshot();
    });
    
    it('should handle click events', () => {
        const onClick = jest.fn();
        const { getByText } = render(
            <ComponentName onClick={onClick}>Click me</ComponentName>
        );
        
        fireEvent.click(getByText('Click me'));
        expect(onClick).toHaveBeenCalledTimes(1);
    });
    
    it('should render different states', () => {
        const { rerender, getByTestId } = render(<ComponentName />);
        expect(getByTestId('component')).toMatchSnapshot();
        
        rerender(<ComponentName active={true} />);
        expect(getByTestId('component')).toMatchSnapshot();
    });
});
```

#### Redux Testing
```javascript
import sinon from 'sinon';
import _ from 'lodash';
import { thunkFunction } from '../thunks/example';
import MockApi from '../../mock/MockApi';

describe('thunk function', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    
    it('should dispatch correct actions on success', async () => {
        const fakeDispatch = sinon.spy();
        const getState = () => ({ roles: {} });
        
        MockApi.setMockApi({
            getRoles: jest.fn().mockReturnValue(Promise.resolve(mockData)),
        });
        
        await thunkFunction('domain')(fakeDispatch, getState);
        
        // Action verification
        expect(_.isEqual(
            fakeDispatch.getCall(0).args[0],
            expectedAction
        )).toBeTruthy();
        
        expect(fakeDispatch.callCount).toBe(3);
    });
    
    it('should handle errors properly', async () => {
        const fakeDispatch = sinon.spy();
        const getState = () => ({ roles: {} });
        
        MockApi.setMockApi({
            getRoles: jest.fn().mockReturnValue(Promise.reject(new Error('API Error'))),
        });
        
        try {
            await thunkFunction('domain')(fakeDispatch, getState);
        } catch (error) {
            expect(error.message).toBe('API Error');
        }
    });
});
```

#### Testing Guidelines
- ✅ **React Testing Library**: Use with Jest for component testing
- ✅ **Snapshot Testing**: For UI regression detection
- ✅ **data-testid Usage**: Use data-testid for element selection
- ✅ **MockApi Utilization**: Standard mock patterns for API calls
- ✅ **Sinon Spies**: Verify dispatches in Redux thunk tests
- ✅ **lodash isEqual**: For deep object comparison

### 6. 🖥️ Server Patterns

#### Express Middleware
```javascript
const express = require('express');
const helmet = require('helmet');
const cookieSession = require('cookie-session');

const expressApp = express();

// Security headers
expressApp.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", (req, res) => `'nonce-${req.headers.rid}'`],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));

// Session management
expressApp.use(cookieSession({
    name: 'session',
    keys: [secrets.sessionKey],
    secure: true,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
}));

// CSRF protection
expressApp.use(csurf({ cookie: false }));
```

#### API Handlers
```javascript
const apiHandler = (req, res, next) => {
    try {
        // Input validation
        if (!req.body.domainName || !validateDomainName(req.body.domainName)) {
            return res.status(400).json({ 
                error: 'Invalid domain name' 
            });
        }
        
        // Business logic
        const result = processRequest(req.body);
        
        // Response
        res.status(200).json({
            success: true,
            data: result,
            _csrf: req.csrfToken(),
        });
        
    } catch (error) {
        errorHandler(error, req, res, next);
    }
};
```

#### Server Guidelines
- ✅ **Helmet Usage**: Configure security headers
- ✅ **CSRF Protection**: Require CSRF tokens for state-changing operations
- ✅ **Secure Cookies**: Configure secure cookies in production
- ✅ **Input Validation**: Validate input fields with regex patterns
- ✅ **Error Handling**: Use errorHandler utilities
- ✅ **Proper Logging**: Use debug module for appropriate log output

### 7. 📋 General Coding Guidelines

#### Naming Conventions
- ✅ **camelCase**: Variables, functions, methods
- ✅ **PascalCase**: Components, classes
- ✅ **SCREAMING_SNAKE_CASE**: Constants
- ✅ **kebab-case**: File names, CSS classes

#### Error Handling
```javascript
// Error handling in async operations
try {
    const result = await apiCall();
    return result;
} catch (error) {
    logger.error('API call failed:', error);
    throw new Error('Operation failed');
}

// Error display in components
if (error) {
    return <Alert type="error">{error.message}</Alert>;
}
```

#### Data Transformation
```javascript
// Transformation in utility functions
export const transformApiData = (apiResponse) => {
    return apiResponse.items.map(item => ({
        id: item.name,
        displayName: item.displayName || item.name,
        lastModified: formatDate(item.modified),
    }));
};

// Transformation in selectors
export const selectFormattedUsers = (state) => {
    return Object.values(state.users).map(user => ({
        ...user,
        fullName: `${user.firstName} ${user.lastName}`,
    }));
};
```

#### Performance Considerations
- ✅ **React.PureComponent**: Optimize performance in appropriate places
- ✅ **Data Caching**: Implement caching with expiration
- ✅ **Avoid Unnecessary Re-renders**: Use proper key properties
- ✅ **Lazy Loading**: Lazy load large components
- ✅ **Memoization**: Memoize expensive calculations

---

## 📝 Development Workflow

### Pre-commit Checklist
- ✅ Verify license headers
- ✅ Define PropTypes
- ✅ Create/update tests
- ✅ Check snapshots
- ✅ Run ESLint/Prettier
- ✅ Check TypeScript errors

### Test Execution
```bash
# Unit tests
npm test

# Tests with coverage
npm run test

# Run specific tests
npm run single-test

# Update snapshots
npm run regen-snap

# Functional tests
npm run functional
```

### Build and Deploy
```bash
# Development environment
npm run dev

# Production build
npm run build

# Production start
npm start

# Lint check
npm run ci-lint

# Format fix
npm run fix-lint
```

This guideline document ensures consistent development in the Athenz UI project. When adding new features or modifying existing code, please follow these patterns.