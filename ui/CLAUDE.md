# Athenz UI - Claude Development Guide

## Project Overview

Athenz UI is a React-based interface for managing Athenz domains, roles, policies, services, and access control. Built with Next.js, it provides a comprehensive UI for the Athenz authorization system.

**IMPORTANT: All source code must be written in English only:**
- Variable names, function names, class names
- Comments and documentation
- String literals and error messages
- API endpoints and parameters
- Configuration keys and values
- Test descriptions

**For UI design guidelines, styling patterns, and component standards, see [DESIGN_SYSTEM.md](./DESIGN_SYSTEM.md).**

## Architecture

### Technology Stack
- **Frontend**: React 18.2.0, Next.js 14.2.26
- **State Management**: Redux Toolkit with Redux Thunk
- **Styling**: Emotion CSS-in-JS, Denali Design System
- **Testing**: Jest with React Testing Library
- **Build Tools**: Next.js, Webpack

### Project Structure
```
/
├── src/
│   ├── components/          # Reusable React components
│   │   ├── constants/       # Application constants
│   │   ├── denali/         # Denali design system components
│   │   ├── domain/         # Domain management components
│   │   ├── group/          # Group management components
│   │   ├── header/         # Header and navigation components
│   │   ├── member/         # Member management components
│   │   ├── microsegmentation/ # Network segmentation components
│   │   ├── modal/          # Modal dialogs
│   │   ├── policy/         # Policy management components
│   │   ├── role/           # Role management components
│   │   ├── service/        # Service management components
│   │   └── utils/          # Utility functions
│   ├── config/             # Configuration files
│   ├── hooks/              # Custom React hooks
│   ├── pages/              # Next.js pages (file-based routing)
│   ├── redux/              # Redux store, actions, reducers, selectors
│   ├── server/             # Express server components
│   └── __tests__/          # Test files
├── static/                 # Static assets
└── keys/                   # SSL certificates and keys
```

## Configuration

### Primary Configuration Files

#### 1. `/src/config/default-config.js`
Main configuration file with environment-specific settings:
- **Server URLs**: ZMS, ZTS, MSD, UMS endpoints
- **Authentication**: Cookie settings, auth headers, SSL configuration
- **UI Settings**: Header links, user data, feature flags
- **Security**: CSRF, CSP, cipher suites
- **Templates**: Available domain templates

Key configuration sections:
```javascript
const config = {
    local: {
        zms: process.env.ZMS_SERVER_URL || 'https://localhost:4443/zms/v1/',
        authHeader: 'Athenz-Principal-Auth',
        cookieName: 'Athenz-Principal-Auth',
        featureFlag: true,
        pageFeatureFlag: {
            microsegmentation: { policyValidation: true },
            roleGroupReview: { roleGroupReviewFeatureFlag: true }
        }
    },
    unittest: { /* test-specific config */ }
}
```

#### 2. `/src/config/config.js`
Configuration loader that:
- Loads default configuration
- Merges with optional `extended-config.js` (if exists)
- Supports environment-based configuration via `APP_ENV`

#### 3. Service Configuration Files
- `/src/config/zms.json` - ZMS service configuration
- `/src/config/zts.json` - ZTS service configuration  
- `/src/config/msd.json` - MSD service configuration
- `/src/config/ums.json` - UMS service configuration

### Environment Variables
- `APP_ENV` - Environment (local, unittest, production)
- `ZMS_SERVER_URL` - ZMS server endpoint
- `ZTS_LOGIN_URL` - ZTS login endpoint
- `MSD_LOGIN_URL` - MSD login endpoint
- `UMS_LOGIN_URL` - UMS login endpoint
- `PORT` - Server port (default: 443)
- `NODE_ENV` - Node environment
- `NEXT_PUBLIC_USER_DOMAIN` - Public user domain

## String Literals and Constants

### Primary Constants File: `/src/components/constants/constants.js`

#### UI Constants
```javascript
export const MODAL_TIME_OUT = 2000;
export const DISPLAY_SPACE = '\u23b5';
export const USER_DOMAIN = process.env.NEXT_PUBLIC_USER_DOMAIN || 'user';
export const DELETE_AUDIT_REFERENCE = 'deleted using Athenz UI';
```

#### Pagination Constants
```javascript
// Basic Pagination Configuration
export const PAGINATION_DEFAULT_ITEMS_PER_PAGE = 25;
export const PAGINATION_ITEMS_PER_PAGE_OPTIONS = [25, 50, 100];

// Pagination UI Labels
export const PAGINATION_ITEMS_PER_PAGE_LABEL = 'Show';
export const PAGINATION_SHOWING_TEXT = 'Showing';
export const PAGINATION_OF_TEXT = 'of';
export const PAGINATION_MEMBERS_TEXT = 'members';
export const PAGINATION_PREVIOUS_TEXT = 'Previous';
export const PAGINATION_NEXT_TEXT = 'Next';

// Pagination Accessibility Labels (ARIA support)
export const PAGINATION_ARIA_PREVIOUS_LABEL = 'Go to previous page';
export const PAGINATION_ARIA_NEXT_LABEL = 'Go to next page';
export const PAGINATION_ARIA_PAGE_LABEL = 'Page';
export const PAGINATION_ARIA_CURRENT_PAGE = 'page';
export const PAGINATION_ARIA_ROLE_BUTTON = 'button';
export const PAGINATION_ARIA_SELECT_PAGE_SIZE_LABEL = 'Select page size';

// Generic Item Types for Pagination (supports multiple data types)
export const PAGINATION_ITEMS_TEXT = 'items';        // Generic fallback
export const PAGINATION_ROLES_TEXT = 'roles';        // For role lists
export const PAGINATION_POLICIES_TEXT = 'policies';  // For policy lists
export const PAGINATION_SERVICES_TEXT = 'services';  // For service lists
export const PAGINATION_GROUPS_TEXT = 'groups';      // For group lists
```

#### Service Types
```javascript
export const SERVICE_TYPE_DYNAMIC = 'dynamic';
export const SERVICE_TYPE_STATIC = 'static';
export const SERVICE_TYPE_MICROSEGMENTATION = 'microsegmentation';
export const SERVICE_TYPE_MICROSEGMENTATION_LABEL = 'Microsegmentation';
export const SERVICE_TYPE_DYNAMIC_LABEL = 'Dynamic Instances';
export const SERVICE_TYPE_STATIC_LABEL = 'Static Instances';
```

#### Segmentation Constants
```javascript
export const SEGMENTATION_TYPE_OUTBOUND = 'outbound';
export const SEGMENTATION_TYPE_INBOUND = 'inbound';
export const SEGMENTATION_PROTOCOL_TYPE_TCP = 'TCP';
export const SEGMENTATION_PROTOCOL_TYPE_UDP = 'UDP';
```

#### Validation Patterns and Regex
```javascript
export const GROUP_NAME_REGEX = '([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*';
export const GROUP_MEMBER_NAME_REGEX = '([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*';
export const MICROSEGMENTATION_SERVICE_NAME_REGEX = '\\*|([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*';
```

#### Static Workload Types
```javascript
export const StaticWorkloadType = [
    { name: 'VIP', value: 'VIP', pattern: '...' },
    { name: 'Enterprise Appliance', value: 'ENTERPRISE_APPLIANCE', pattern: '...' },
    // ... see constants.js for complete list
];
```

#### Workflow and UI Labels
```javascript
export const WORKFLOW_PENDING_MEMBERS_APPROVAL_ADMIN_VIEW_TAB = 'Pending Members Approval (Admin View)';
export const WORKFLOW_PENDING_MEMBERS_APPROVAL_DOMAIN_VIEW_TAB = 'Pending Members Approval (Domain View)';
export const WORKFLOW_TITLE = 'Action Required';
```

#### Form Placeholders and Descriptions
```javascript
export const GROUP_MEMBER_PLACEHOLDER = `${USER_DOMAIN}.<userid> or <domain>.<service>`;
export const ADD_ROLE_MEMBER_PLACEHOLDER = `${USER_DOMAIN}.<userid> or <domain>.<service> or <domain>:group.<group>`;
export const ADD_ROLE_JUSTIFICATION_PLACEHOLDER = 'Enter justification here';
```

#### Enums and States
```javascript
export const PENDING_APPROVAL_TYPE_ENUM = Object.freeze({
    EXPIRY: 'expiry',
    REVIEW: 'review',
});

export const PENDING_STATE_ENUM = Object.freeze({
    ADD: 'ADD',
    DELETE: 'DELETE',
});
```


## Development Commands

### Available Scripts
```bash
# Development
npm run dev              # Start development server with debug
npm run build           # Production build
npm start              # Start production server

# Testing
npm test               # Run unit tests with coverage
npm run regen-snap     # Update Jest snapshots
npm run single-test    # Run specific test
npm run ci-unit-test   # CI unit tests

# Code Quality
npm run fix-lint       # Format code with Prettier
npm run ci-lint        # Check code formatting

# Functional Testing
npm run functional     # Run WebDriver tests
npm run func:local:ui  # Run local functional tests
```

### Development Setup
1. Install dependencies: `npm install`
2. Set up SSL certificates in `/keys/` directory
3. Configure environment variables
4. Start development server: `npm run dev`
5. Access at `https://localhost:443`

## Testing Strategy

### Unit Tests
- Located in `/src/__tests__/`
- Uses Jest + React Testing Library
- Update snapshots after UI changes: `npm run regen-snap`
- Mock data in `/src/mock/`

### Functional Tests
- WebDriver-based tests in `/src/__tests__/spec/`
- Cross-browser testing support

## Key Features

- **Domain Management**: Create and manage Athenz domains, templates, settings
- **Access Control**: Role-based access control (RBAC), policy management, group management
- **Member Management**: Member lists with expiration/review, pagination support
- **Service Management**: Service registration, dynamic/static instances, microsegmentation
- **Workflow Management**: Pending approval workflows, review processes, audit trails
- **Security**: SSL/TLS encryption, CSRF protection, Athenz token authentication

## API Integration

- **ZMS (AuthoriZation Management System)**: Domain, role, policy management
- **ZTS (AuthoriZation Token Service)**: Token generation and validation

## Customization

### Extending Configuration
Create `/src/config/extended-config.js` to override default settings:
```javascript
module.exports = function() {
    return {
        // Custom configuration overrides
        customFeature: true,
        headerLinks: [...],
    };
};
```

### Adding New Constants
Add new constants to `/src/components/constants/constants.js` following the existing patterns:
```javascript
export const NEW_FEATURE_CONSTANT = 'value';
export const NEW_FEATURE_REGEX = /pattern/;
```

### Feature Flags

#### Global Feature Flags
Control application-wide features via `default-config.js`:
```javascript
featureFlag: true  // Global enable/disable
```

#### Page-Specific Feature Flags
Control features per page using the `pageFeatureFlag` pattern:
```javascript
pageFeatureFlag: {
    newFeature: {
        enabled: true
    }
}
```

**Important**: Page feature flags require different handling than global configuration:
- **Access Pattern**: Use `api.getPageFeatureFlag('pageName')` instead of Redux selectors
- **Component Integration**: Store in local component state with useEffect
- **Error Handling**: Always provide fallback values for failed API calls

### Configuration Architecture

**Dual configuration system**:
1. **Server-Side**: Global settings, feature flags in `default-config.js`
2. **Client-Side**: Access via Redux (`headerDetails`, `featureFlag`) or direct API calls (`pageFeatureFlag`)

**Critical Implementation Pattern**:
```javascript
// ✅ CORRECT: Page feature flag access
useEffect(() => {
    let isMounted = true;
    
    api.getPageFeatureFlag('pageName')
        .then((data) => {
            if (isMounted && data && typeof data.featureName === 'boolean') {
                setFeatureEnabled(data.featureName);
            }
        })
        .catch(() => {
            if (isMounted) {
                setFeatureEnabled(true); // Fail-safe default
            }
        });
        
    return () => { isMounted = false; };
}, []);
```

## Development Best Practices

### Component Development Guidelines

#### Custom Hooks
- Place in `/src/hooks/` with descriptive names starting with `use`
- Include comprehensive unit tests
- Document parameters and return values

**Critical React Hooks Rules**:
- Never use conditional early returns - always call hooks in same order
- Handle conditional logic inside hook functions
- Maintain hook call consistency across renders

```javascript
// ❌ WRONG: Conditional early return violates Hook rules
export const useFeature = (enabled) => {
    if (!enabled) {
        return { disabled: true }; // Violates Hook rules!
    }
    const [state] = useState(); // Hooks called conditionally
    // ...
};

// ✅ CORRECT: Conditional logic inside hook functions
export const useFeature = (enabled) => {
    const [state] = useState(); // Always called
    
    const result = useMemo(() => {
        if (!enabled) {
            return { disabled: true };
        }
        // Normal processing
    }, [enabled, state]);
    
    return result;
};
```

#### Reusable UI Components

**CRITICAL: Denali Design System Priority**
- **Always use Denali CSS classes over custom styled components**
- Prefer Denali's prepared styles instead of creating independent CSS
- Only use Emotion CSS-in-JS when Denali doesn't provide equivalent functionality
- **Migration Priority**: Convert existing styled components to Denali CSS classes

**Implementation Requirements**:
- **Follow the Denali Design System** - See [DESIGN_SYSTEM.md](./DESIGN_SYSTEM.md) for implementation details
- All components must comply with Denali standards for colors, typography, spacing, and interactions
- Use Denali CSS classes: `.button`, `.input`, `.toggle`, `.is-solid`, `.is-outline`, `.is-small`, etc.
- Implement proper accessibility (ARIA labels, keyboard navigation)
- Include `testId` props for testing

**Denali CSS Class Examples**:
```javascript
// ✅ CORRECT: Using Denali CSS classes
<button className="button is-outline is-small">
    Click me
</button>

<div className="input has-arrow">
    <select>...</select>
</div>

<div className="toggle is-small">
    <ul>
        <li className="is-active"><a>Active</a></li>
        <li><a>Inactive</a></li>
    </ul>
</div>

// ❌ WRONG: Custom styled components when Denali exists
const CustomButton = styled.button`
    background: #fff;
    border: 1px solid #ccc;
    // ... custom styles
`;
```

#### Testing Strategy
- Follow Test-Driven Development (TDD) for new features
- Achieve high test coverage (90%+ for new components)
- Use React Testing Library for component testing
- Test edge cases and error conditions

**Best Practices**:
- Always provide `testId` props for deterministic testing
- Test hooks separately from UI components when debugging
- Use React DevTools to inspect hook states and re-render causes

#### Component Generalization Patterns

**Purpose**: Convert specific components into reusable, generic components while maintaining backward compatibility.

**Key Principles**:
- **Backward Compatibility**: Existing usage must continue to work without changes
- **Gradual Migration**: Allow both old and new prop interfaces
- **Clear Deprecation**: Mark old props as deprecated with clear alternatives

**Generalization Strategy Example - Pagination Component**:

```javascript
// ✅ BEFORE: Member-specific pagination
<Pagination memberType="members" />

// ✅ AFTER: Generic pagination with backward compatibility
<Pagination 
    itemType="roles"      // New generic prop (preferred)
    memberType="members"  // Deprecated but still works
/>

// Implementation pattern for backward compatibility:
const Pagination = ({ itemType, memberType = 'members' }) => {
    // Prioritize new prop, fall back to old prop
    const displayItemType = itemType || memberType;
    
    return (
        <div>
            Showing 1-10 of 50 {displayItemType}
        </div>
    );
};
```

**Generic Prop Design Patterns**:

```javascript
// ✅ Generic constants for different item types
export const PAGINATION_ROLES_TEXT = 'roles';
export const PAGINATION_POLICIES_TEXT = 'policies';
export const PAGINATION_SERVICES_TEXT = 'services';

// ✅ Component usage with different types
<Pagination itemType="roles" />     // For role lists
<Pagination itemType="policies" />  // For policy lists
<Pagination itemType="services" />  // For service lists
```

**Migration Documentation Pattern**:

```javascript
/**
 * @param {string} itemType - Type of items being paginated (preferred)
 * @param {string} memberType - Deprecated: use itemType instead
 */
const GenericComponent = ({ itemType, memberType }) => {
    // Implementation with deprecation warning in development
    if (memberType && !itemType && process.env.NODE_ENV === 'development') {
        console.warn('memberType is deprecated, use itemType instead');
    }
};
```

**Validation Checklist for Component Generalization**:
- ✅ Existing tests continue to pass without modification
- ✅ No breaking changes in public API
- ✅ Clear documentation of new vs deprecated props
- ✅ Generic constants available for different use cases
- ✅ JSDoc comments explain migration path

#### State Management Best Practices

**useEffect Dependencies**:
```javascript
// ❌ BAD - causes unnecessary re-renders
useEffect(() => {
    setCurrentPage(1);
}, [data]);

// ✅ GOOD - only reacts to data length changes
useEffect(() => {
    setCurrentPage(1);
}, [data.length]);
```

**Array Reference Stability**:
```javascript
// ✅ Always memoize sort operations
const sortedData = useMemo(() => 
    [...data].sort((a, b) => a.name.localeCompare(b.name)),
    [data]
);
```

**Anti-patterns to Avoid**:
- Duplicate state management between components
- Using entire arrays as dependencies when only length matters
- Missing return values from custom hooks
- Creating redundant Redux selectors that duplicate existing functionality
- Over-engineering hooks with complex enabled/disabled logic when simple implementations work better

#### Performance Optimization

**Memoization**:
- Use `useMemo` for sorting, filtering, and data transformations
- Always spread arrays before sorting: `[...array].sort()`
- Prefer specific dependencies (`data.length` vs `data`)

**API Calls**:
- Always implement cleanup to prevent setting state on unmounted components

```javascript
// ✅ CORRECT: Safe API call with cleanup
useEffect(() => {
    let isMounted = true;
    
    api.fetchData()
        .then((data) => {
            if (isMounted) {
                setState(data);
            }
        })
        .catch((err) => {
            if (isMounted) {
                setError(err);
            }
        });
        
    return () => {
        isMounted = false;
    };
}, []);
```

#### Pagination Implementation

**Key Components**:
- `usePagination` hook in `/src/hooks/usePagination.js` - General pagination logic
- `useMemberPagination` hook in `/src/hooks/useMemberPagination.js` - Unified member filtering, sorting, and pagination
- `Pagination` component in `/src/components/member/Pagination.js` - Denali-compliant pagination UI
- `PageSizeSelector` component in `/src/components/member/PageSizeSelector.js` - Page size controls
- `PaginatedMemberTable` component in `/src/components/member/PaginatedMemberTable.js` - Wrapper for member tables with pagination

**Denali Design System Implementation**:
```javascript
// ✅ CORRECT: Using Denali toggle system for page numbers
<div className="toggle is-small">
    <ul>
        {visiblePages.map((page) =>
            page === '...' ? (
                <Ellipsis key={`ellipsis-${index}`}>...</Ellipsis>
            ) : (
                <li
                    key={page}
                    className={page === currentPage ? 'is-active' : ''}
                    onClick={() => handlePageClick(page)}
                    role="button"
                    tabIndex={0}
                >
                    <a>{page}</a>
                </li>
            )
        )}
    </ul>
</div>

// ✅ CORRECT: Navigation buttons with Denali classes
<button
    className="button is-outline is-small"
    disabled={!hasPrevious}
    onClick={handlePreviousClick}
>
    <Icon icon='arrow-left' />
    Previous
</button>

// ✅ CORRECT: Page size selector with Denali input
<div className={`input has-arrow ${compact ? 'is-small' : ''}`}>
    <select value={value} onChange={handleChange}>
        {options.map((option) => (
            <option key={option} value={option}>
                {option}
            </option>
        ))}
    </select>
</div>
```

**Critical Architecture Requirements**:
```javascript
// For simple pagination: use usePagination hook
const pagination = usePagination(data, initialItemsPerPage);

// For member lists: use unified useMemberPagination hook
const memberPagination = useMemberPagination(
    members, 
    collectionDetails, 
    paginationEnabled, 
    initialFilter
);

// Essential patterns for performance:
// 1. Use data.length, not data, to prevent page resets
useEffect(() => {
    setCurrentPage(1);
}, [data.length]);

// 2. Always memoize sort operations
const sortedData = useMemo(() => 
    [...data].sort((a, b) => a.memberName.localeCompare(b.memberName)),
    [data]
);

// 3. Use PaginatedMemberTable wrapper for simplified props
<PaginatedMemberTable
    memberData={memberPagination.approvedMembers}
    paginationConfig={{ showPagination: true }}
    tableConfig={{ tableId: 'approved-members', renderMember }}
/>
```

**Denali Component Patterns**:
- **Page Numbers**: Use `toggle` system with `is-active` for current page
- **Navigation**: Use `button is-outline is-small` classes
- **Dropdowns**: Use `input has-arrow` with proper sizing (`is-small`)
- **Unified Styling**: All components follow Denali size and state conventions

#### State Management
- Use Redux for global state
- Implement proper selectors
- Handle loading states consistently

#### Error Handling
- Implement error boundaries
- Display user-friendly error messages
- Handle network failures gracefully
- Always provide fallback values for configuration flags

#### String Literal Management Best Practices

**Purpose**: Centralize and standardize all user-facing text for maintainability, consistency, and internationalization readiness.

**Core Principles**:
- **No Hardcoded Strings**: All user-visible text must be defined as constants
- **Accessibility First**: ARIA labels and accessibility text must be centralized
- **Internationalization Ready**: Structure constants for future translation support
- **Consistent Naming**: Follow established patterns for constant naming

**Constant Categories and Patterns**:

```javascript
// ✅ UI Labels - User-visible text
export const PAGINATION_SHOWING_TEXT = 'Showing';
export const PAGINATION_OF_TEXT = 'of';
export const BUTTON_SAVE_TEXT = 'Save';
export const BUTTON_CANCEL_TEXT = 'Cancel';

// ✅ Accessibility Labels - ARIA and screen reader text
export const PAGINATION_ARIA_PREVIOUS_LABEL = 'Go to previous page';
export const PAGINATION_ARIA_NEXT_LABEL = 'Go to next page';
export const BUTTON_ARIA_CLOSE_DIALOG = 'Close dialog';

// ✅ Item Type Descriptors - Context-specific labels
export const PAGINATION_MEMBERS_TEXT = 'members';
export const PAGINATION_ROLES_TEXT = 'roles';
export const PAGINATION_POLICIES_TEXT = 'policies';

// ✅ Form Placeholders and Descriptions
export const GROUP_MEMBER_PLACEHOLDER = 'user.example or domain.service';
export const ROLE_JUSTIFICATION_PLACEHOLDER = 'Enter justification here';
```

**Naming Convention Patterns**:

```javascript
// Pattern: [COMPONENT]_[CATEGORY]_[DESCRIPTION]_[TYPE]
export const PAGINATION_ARIA_PREVIOUS_LABEL = '...';  // Component_Category_Description_Type
export const MEMBER_TABLE_HEADER_USER_NAME = '...';   // Component_Category_Description
export const WORKFLOW_PENDING_APPROVAL_TITLE = '...'; // Feature_Context_Description
```

**String Literal Audit Process**:

1. **Identification**: Search for hardcoded strings in quotes
```bash
# Find potential hardcoded UI text
grep -r "aria-label=['\"]" src/components/
grep -r "placeholder=['\"]" src/components/
grep -r "'[A-Z]" src/components/ | grep -v "className"
```

2. **Classification**: Determine constant category
   - UI Labels (user-visible)
   - Accessibility Labels (ARIA)
   - Form Text (placeholders, descriptions)
   - Error Messages
   - Configuration Values

3. **Centralization**: Move to appropriate constants section
```javascript
// ❌ BEFORE: Hardcoded strings
<button aria-label="Go to next page">Next</button>
<input placeholder="Enter role name" />

// ✅ AFTER: Centralized constants
<button aria-label={PAGINATION_ARIA_NEXT_LABEL}>{PAGINATION_NEXT_TEXT}</button>
<input placeholder={ROLE_NAME_PLACEHOLDER} />
```

**Internationalization Preparation**:

```javascript
// ✅ Group related constants for future i18n
export const PAGINATION_LABELS = {
    SHOWING: 'Showing',
    OF: 'of',
    PREVIOUS: 'Previous',
    NEXT: 'Next',
    ITEMS: 'items'
};

// ✅ Accessibility labels grouped for translation
export const PAGINATION_ARIA = {
    PREVIOUS: 'Go to previous page',
    NEXT: 'Go to next page',
    PAGE: 'Page',
    SELECT_SIZE: 'Select page size'
};
```

**Quality Assurance Checklist**:
- ✅ No hardcoded user-visible strings in JSX
- ✅ All ARIA labels use constants
- ✅ Form placeholders and descriptions centralized
- ✅ Constants follow naming conventions
- ✅ Related constants grouped logically
- ✅ JSDoc comments explain usage context

### Code Quality

#### Development Workflow
- Follow ESLint rules and Prettier formatting
- Use meaningful variable and function names
- Write self-documenting code

#### Code Quality Improvement Workflow

**Purpose**: Systematic approach to identifying and resolving code quality issues discovered during development.

**1. Unused Variable Detection**

```bash
# Regular audit process
npm run ci-lint              # Check formatting issues
npm run build                # Verify no unused imports/variables cause build failures

# Manual inspection for unused variables
# Look for variables/imports that are declared but never referenced
```

**Common Patterns to Check**:
```javascript
// ❌ Unused imports
import { UnusedConstant } from './constants';  // Remove if not used

// ❌ Unused variables
const unusedVariable = computeValue();         // Remove if not referenced

// ❌ Duplicate constants/functions
export const DUPLICATE_CONSTANT = 'value';    // Consolidate duplicates

// ❌ Unused styled components
const UnusedStyledDiv = styled.div`...`;       // Remove if not used
```

**2. String Literal Audit Process**

```bash
# Find hardcoded strings that should be constants
grep -r "aria-label=['\"]" src/components/
grep -r "placeholder=['\"]" src/components/
grep -r "'[A-Z][a-zA-Z ]*'" src/components/ | grep -v className

# Focus on pagination-related hardcoded strings
grep -r "'Previous'" src/components/
grep -r "'Next'" src/components/
grep -r "'Showing'" src/components/
```

**String Literal Priority Matrix**:
```
High Priority (Immediate Action Required):
├─ User-visible text (buttons, labels, messages)
├─ Accessibility text (ARIA labels, screen reader)
└─ Form text (placeholders, validation messages)

Medium Priority (Plan for Future):
├─ Error messages
├─ Configuration values
└─ Debug/development text

Low Priority (As Needed):
├─ Technical constants (CSS class names)
├─ API endpoint paths
└─ Environment-specific values
```

**3. Component Generalization Assessment**

```javascript
// Evaluation criteria for component generalization
const shouldGeneralize = {
    // ✅ Good candidates
    usedInMultipleContexts: true,     // Component used for different data types
    hasSpecificProps: true,           // Props tied to specific use case
    easyToGeneralize: true,           // Simple prop changes can make it generic
    
    // ❌ Poor candidates  
    highlySpecialized: false,         // Complex domain-specific logic
    rarelyUsed: false,               // Used in only one place
    complexDependencies: false        // Tightly coupled to specific data structures
};
```

**4. Quality Gates Checklist**

**Before Committing**:
```bash
# Automated checks
npm run fix-lint              # Fix formatting issues
npm run ci-lint               # Verify no formatting issues remain
npm run build                 # Ensure production build succeeds
npm test                      # Verify tests pass

# Manual verification
□ No unused variables or imports
□ No hardcoded user-visible strings
□ No duplicate constants or functions
□ Consistent naming conventions
□ JSDoc comments for complex functions
```

**After Implementation**:
```bash
# Regression testing
□ Existing functionality unchanged
□ New features work as expected
□ Accessibility compliance maintained
□ Performance impact acceptable
□ Documentation updated
```

**5. Refactoring Safety Protocol**

```javascript
// ✅ Safe refactoring patterns
// 1. Additive changes (new props with defaults)
const Component = ({ newProp = 'default', ...existingProps }) => {
    // Implementation maintains backward compatibility
};

// 2. Deprecation with warnings
const Component = ({ oldProp, newProp }) => {
    if (oldProp && process.env.NODE_ENV === 'development') {
        console.warn('oldProp is deprecated, use newProp instead');
    }
    const value = newProp || oldProp;
};

// 3. Gradual migration support
const displayValue = newConstant || oldConstant || defaultValue;
```

**Emergency Rollback Plan**:
- Keep deprecated props functional during transition period
- Maintain comprehensive test coverage
- Document all breaking changes clearly
- Provide migration guides for complex changes

## Key Architectural Patterns

### Pagination System Architecture

The Athenz UI implements a two-tier pagination system optimized for different use cases:

#### 1. General Purpose: `usePagination` Hook
- **Purpose**: Simple pagination for any data array
- **Features**: Basic pagination navigation, page size control, data slicing
- **Use Case**: Generic lists, search results, simple tables
- **Location**: `/src/hooks/usePagination.js`

#### 2. Member-Specific: `useMemberPagination` Hook  
- **Purpose**: Unified filtering, sorting, and pagination for member lists
- **Features**: Text filtering, member sorting, separate approved/pending pagination, trust collection handling
- **Use Case**: Member management components (MemberList, role members, group members)
- **Location**: `/src/hooks/useMemberPagination.js`

#### 3. UI Component: `PaginatedMemberTable` Wrapper
- **Purpose**: Simplifies prop passing and encapsulates pagination concerns
- **Features**: Unified interface for member tables with pagination
- **Benefits**: Reduces component complexity, standardizes member table patterns
- **Location**: `/src/components/member/PaginatedMemberTable.js`

### Refactoring Principles Applied

Based on the recent pagination refactoring, these principles guide code improvement:

#### 1. Unified Logic Extraction
- Extract common patterns into shared hooks
- Eliminate duplicate state management between components
- Create single sources of truth for complex operations

#### 2. Wrapper Components for Simplification
- Use wrapper components to simplify prop interfaces
- Encapsulate complex logic within specialized components
- Reduce cognitive load on parent components

#### 3. Performance-First Memoization
- Always memoize expensive operations (sorting, filtering)
- Use specific dependencies (`data.length` vs `data`)
- Implement stable references for array operations

#### 4. Hook Simplification
- Remove over-engineering and unnecessary complexity
- Focus hooks on specific, well-defined responsibilities
- Eliminate redundant enabled/disabled logic patterns

### Redux Best Practices

#### Selector Management
- Avoid creating redundant selectors that duplicate existing functionality
- Use descriptive names that clearly indicate purpose
- Remove unused selectors during refactoring

#### State Architecture
- Keep Redux for global application state
- Use local component state for UI-specific concerns
- Implement proper cleanup to prevent memory leaks

## Clarifying Vague Requirements: Pre-Implementation Checklist

When receiving unclear or broad implementation requests, use this checklist to clarify requirements before starting work:

### 1. Scope and Context Clarification
**Questions to ask when you receive vague requests like "make X configurable" or "improve Y":**

```
❓ Scope Questions:
- Who needs to configure this? (Developers? Admins? End users?)
- When do they need to configure it? (Build time? Runtime? Per session?)
- How often will this configuration change? (Never? Rarely? Frequently?)
- What specific values need to be configurable?

❓ Context Questions:
- What problem is this solving?
- What's currently not working with the existing implementation?
- Are there specific scenarios where current behavior fails?
- Is this driven by a new requirement or improving existing UX?
```

### 2. Technical Approach Decision Tree
**Before implementing, determine the appropriate complexity level:**

```
Decision Matrix:
┌─ Will this change once during development? → Use constants (Level 1)
├─ Will this vary by environment (dev/prod)? → Use config files (Level 2)  
├─ Will this change without code deployment? → Use environment variables (Level 3)
├─ Will admins need to change this? → Use server configuration (Level 4)
└─ Will end users need to customize this? → Use UI settings (Level 5)

⚠️  Default to Level 1 unless compelling evidence for higher complexity
```

### 3. Performance and Complexity Impact Assessment
**Questions to evaluate before choosing implementation approach:**

```
Performance Impact:
- Will this add runtime overhead? (API calls, computations, re-renders)
- Will this increase bundle size significantly?
- Will this affect page load performance?

Complexity Impact:  
- How many files will need modification?
- Will this require new dependencies?
- Will this need new testing infrastructure?
- How will this affect debugging and troubleshooting?

Maintenance Impact:
- Will this require documentation updates?
- Will this need ongoing maintenance?
- Will this create breaking changes for other developers?
```

### 4. Proposed Implementation Validation
**Before starting implementation, confirm your approach:**

```
Validation Checklist:
□ Is the simplest solution that meets requirements
□ Aligns with existing codebase patterns
□ Maintains or improves performance
□ Follows Denali Design System standards
□ Has clear success criteria
□ Includes rollback plan if needed

Example Confirmation:
"Based on the requirement to 'make pagination configurable', I propose:
- Changing constants in /src/components/constants/constants.js
- Current default is 25 items per page with options [25, 50, 100]
- Constants can be easily modified for different defaults
- No runtime configuration needed
- Maintains existing performance
- One-line change for developers to customize further

Does this meet your expectations, or did you envision a different level of configurability?"
```

### 5. Common Anti-Patterns to Avoid

**Based on pagination implementation experience:**

#### ❌ Over-Engineering Red Flags
```
Warning signs you're over-complicating:
- Adding Redux state for simple constants
- Creating API endpoints for static configuration
- Building admin UI for developer settings
- Adding async loading for compile-time values
- Complex merge logic for simple object assignment

If you find yourself implementing these, step back and reconsider.
```

#### ✅ Simple, Effective Alternatives
```javascript
// Instead of complex configuration systems:
export const PAGINATION_DEFAULT_ITEMS_PER_PAGE = 25;
export const PAGINATION_ITEMS_PER_PAGE_OPTIONS = [25, 50, 100];

// Direct usage without ceremony:
const pagination = usePagination(data, PAGINATION_DEFAULT_ITEMS_PER_PAGE);
```

### 6. Implementation Strategy Template

**When you've clarified requirements, follow this pattern:**

```
Phase 1: Investigation (Always start here)
□ Analyze existing implementation
□ Identify optimization opportunities  
□ Document current patterns and pain points

Phase 2: Minimal Implementation
□ Implement simplest solution that works
□ Ensure no regressions
□ Add basic tests

Phase 3: Optimization (If needed)
□ Remove redundant code discovered during investigation
□ Improve performance and maintainability
□ Enhance test coverage

Phase 4: Validation
□ Verify requirements met
□ Check performance impact
□ Update documentation
```

This approach prevents over-engineering by starting simple and only adding complexity when proven necessary.

This guide provides the essential information needed to understand and develop the Athenz UI codebase effectively.
