# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Athenz is an open source platform for X.509 certificate based service authentication and fine-grained role-based access control (RBAC) in dynamic infrastructures. It consists of three main components:

1. **ZMS (Athenz Management System)**: Centralized authorization system for domains, roles, and policies
2. **ZTS (Athenz Token System)**: Decentralized token service for issuing authentication tokens and X.509 certificates
3. **UI**: React-based web interface for managing Athenz resources

## Development Commands

### Java/Maven Build System
- **Build all components**: `mvn clean install`
- **Run tests**: `mvn test`
- **Skip tests**: `mvn install -DskipTests`
- **Build with Docker profile**: `mvn install -DdockerBuild=true`
- **Generate code coverage**: Tests automatically run with JaCoCo coverage (minimum 100% line coverage required)
- **Checkstyle validation**: Runs automatically during build using `athenz-checkstyle.xml`

### UI Development (Node.js/React)
Navigate to `ui/` directory:
- **Development server**: `npm run dev` 
- **Build for production**: `npm run build`
- **Run tests**: `npm test`
- **Fix linting**: `npm run fix-lint`
- **Check linting**: `npm run ci-lint`
- **Functional tests**: `npm run functional`

### Go Components
Many Go components have individual Makefiles:
- **Build Go clients/libraries**: `make` in respective directories
- **Run Go tests**: `make test` (where available)

### Docker Development
Navigate to `docker/` directory:
- **Build all Docker images**: `make build`
- **Deploy development environment**: `make deploy-dev`  
- **Deploy local environment**: `make deploy-local`
- **Prepare UI development environment**: `make prepare-ui-dev-env`
- **Verify deployment**: `make verify`
- **Clean up**: `make clean`

## Architecture & Components

### Core Services
- **ZMS Server** (`servers/zms/`): Centralized management service, source of truth for authorization data
- **ZTS Server** (`servers/zts/`): Token and certificate issuing service for decentralized authorization
- **UI** (`ui/`): React-based management interface

### Client Libraries
- **Java clients** (`clients/java/`): zms, zts, zpe, msd clients
- **Go clients** (`clients/go/`): zms, zts, msd clients  
- **Node.js clients** (`clients/nodejs/`): zts, zpe clients

### Core Libraries
- **Java libs** (`libs/java/`): auth_core, server_common, cert_refresher, instance_provider
- **Go libs** (`libs/go/`): sia (Service Identity Agent), zmscli, zmssvctoken, athenzutils
- **Node.js libs** (`libs/nodejs/`): auth_core

### Service Identity Agents (SIA)
Located in `provider/` - platform-specific identity providers:
- **AWS**: sia-ec2, sia-eks, sia-fargate
- **GCP**: sia-gce, sia-gke, sia-run  
- **Azure**: sia-vm
- **CI/CD**: sia-actions (GitHub), sia-buildkite, sia-harness

### Utilities
Located in `utils/` - command-line tools:
- **zms-cli**: ZMS management CLI
- **zts-roletoken**: Role token management
- **zts-accesstoken**: Access token management
- **zts-rolecert**: Role certificate management
- **zts-svccert**: Service certificate management

## Code Generation

The project uses RDL (REST Description Language) for API definition and code generation:
- **API definitions**: `servers/zms/src/main/rdl/ZMS.rdl`, `servers/zts/src/main/rdl/ZTS.rdl`
- **Code generators**: Located in `rdl/` directory
- **Regenerate stubs**: Run `scripts/make_stubs.sh` in relevant server directories

## Database Schema

- **ZMS Database**: Schema in `servers/zms/schema/zms_server.sql`
- **ZTS Database**: Schema in `servers/zts/schema/zts_server.sql`
- **Schema updates**: Incremental updates in `servers/*/schema/updates/`

## Testing

### Java Testing
- Uses TestNG framework
- Mockito for mocking
- Minimum 100% line coverage enforced via JaCoCo
- Test resources in `src/test/resources/`

### UI Testing
- Jest for unit tests
- WebdriverIO for functional tests
- React Testing Library for component tests
- Tests in `src/__tests__/`

### Go Testing
- Standard Go testing framework
- Test files follow `*_test.go` pattern

## Configuration

### Server Configuration
- **ZMS config**: `servers/zms/conf/zms.properties`
- **ZTS config**: `servers/zts/conf/zts.properties`
- **UI config**: `ui/src/config/config.js`

### Security
- X.509 certificates for service authentication
- Private keys stored securely (never in code)
- Certificate signing and validation throughout
- OAuth2 and JWT token support

## Development Workflow

1. **Local Development**: Use Docker setup in `docker/` for full local environment
2. **UI Development**: Use `docker/prepare-ui-dev-env.sh` for UI-focused development
3. **Testing**: Always run tests before committing (`mvn test` for Java, `npm test` for UI)
4. **Code Style**: Checkstyle enforced for Java, Prettier for JavaScript/React
5. **Documentation**: Update relevant README files when adding new components

## Build Profiles

- **Default**: Builds all components
- **docker-build**: Optimized for Docker container builds
- **maven-central**: For publishing releases

When working with this codebase, always consider the distributed nature of the system and the security implications of authentication and authorization changes.
