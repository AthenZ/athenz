# X509 Service Certificate Email Validation Implementation

## Overview
This implementation adds email validation support for X509 service certificates in Athenz. Service certificates should not contain email addresses in the CSR (Certificate Signing Request), so this feature provides a configurable mechanism to either log warnings or reject such requests.

## Components Created

### 1. Interface - X509CertEmailValidator
**Location:** `libs/java/server_common/src/main/java/com/yahoo/athenz/common/server/cert/X509CertEmailValidator.java`

Defines the contract for validating email addresses in service certificate requests:
- Method: `validateServiceCertificateEmails(String domainName, String serviceName, List<String> emails)`
- Returns `true` if emails are acceptable (either none present or policy allows them)
- Returns `false` if emails should cause rejection

### 2. Factory Interface - X509CertEmailValidatorFactory
**Location:** `libs/java/server_common/src/main/java/com/yahoo/athenz/common/server/cert/X509CertEmailValidatorFactory.java`

Factory pattern for creating X509CertEmailValidator instances, enabling pluggable implementations.

### 3. Default Implementation - DefaultX509CertEmailValidator
**Location:** `libs/java/server_common/src/main/java/com/yahoo/athenz/common/server/cert/impl/DefaultX509CertEmailValidator.java`

Default validator implementation with the following behavior:
- Logs all email addresses found in service certificate CSRs as errors
- Can be configured to either:
  - **Just log** (default): Returns `true` to allow validation to continue
  - **Reject**: Returns `false` to fail validation

Configuration via constructor parameter `rejectEmails`:
- `false` (default): Logs warnings but allows CSR to proceed
- `true`: Logs warnings and rejects the CSR

### 4. Default Factory - DefaultX509CertEmailValidatorFactory
**Location:** `libs/java/server_common/src/main/java/com/yahoo/athenz/common/server/cert/impl/DefaultX509CertEmailValidatorFactory.java`

Creates DefaultX509CertEmailValidator instances with configuration from system property:
- Property: `athenz.zts.x509_cert_email_validator_reject_emails`
- Default: `false` (just log)

## Integration Points

### ZTSConsts
**Location:** `servers/zts/src/main/java/com/yahoo/athenz/zts/ZTSConsts.java`

Added constant:
```java
ZTS_PROP_CERT_EMAIL_VALIDATOR_FACTORY_CLASS = "athenz.zts.cert_email_validator_factory_class"
```

### ZTSImpl
**Location:** `servers/zts/src/main/java/com/yahoo/athenz/zts/ZTSImpl.java`

Changes:
1. Added field: `protected X509CertEmailValidator certEmailValidator = null;`
2. Added method: `void loadX509CertEmailValidator()`
3. Called loader in initialization (similar to `loadCertificateDataValidator()`)
4. Injected validator into three X509ServiceCertRequest instantiation points:
   - `postInstanceX509CertificateRegister()` (line ~5079)
   - `postCertificateRequestWithoutToken()` (line ~5837)
   - `postCertificateRequest()` (line ~6367)

### X509ServiceCertRequest
**Location:** `servers/zts/src/main/java/com/yahoo/athenz/zts/cert/X509ServiceCertRequest.java`

Changes:
1. Added field: `private X509CertEmailValidator emailValidator;`
2. Added setter: `setEmailValidator(X509CertEmailValidator emailValidator)`
3. Added email validation check in `validate()` method:
   - Extracts email addresses from CSR using `Crypto.extractX509CSREmails()`
   - Calls validator if one is injected
   - Returns error if validator rejects emails

## Testing

### Server Common Tests
- `DefaultX509CertEmailValidatorTest`: Tests the validator with various scenarios
- `DefaultX509CertEmailValidatorFactoryTest`: Tests factory configuration

### ZTS Server Tests
Added tests to `X509ServiceCertRequestTest`:
- `testValidateEmailValidatorNotSet()`: Validates backward compatibility
- `testValidateEmailValidatorRejectEmails()`: Tests rejection behavior
- `testValidateEmailValidatorAcceptEmails()`: Tests logging behavior

## Configuration

To use the email validator in ZTS:

```properties
# Enable the default email validator factory
athenz.zts.cert_email_validator_factory_class=com.yahoo.athenz.common.server.cert.impl.DefaultX509CertEmailValidatorFactory

# Configure to just log emails (default)
athenz.zts.x509_cert_email_validator_reject_emails=false

# Or configure to reject service certificates with emails
athenz.zts.x509_cert_email_validator_reject_emails=true
```

## Behavior

### Default Behavior (reject_emails=false)
- Service certificates with email addresses in CSR are allowed
- Error messages are logged for audit trail
- CSR validation continues and may succeed

### Strict Behavior (reject_emails=true)
- Service certificates with email addresses in CSR are rejected
- Error messages are logged
- CSR validation fails with "Invalid email addresses in service certificate request"

## Backward Compatibility

The implementation is fully backward compatible:
- If no validator factory is configured, email validation is skipped
- If a validator is not injected into X509ServiceCertRequest, validation is skipped
- Existing CSRs without email addresses are unaffected
