# ZPU Policy File
-----------------

* [Policy File Signature Validation](#policy-file-signature-validation)
    * [ZTS Signature Validation](#zts-signature-validation)
    * [ZMS Signature Validation](#zms-signature-validation)
* [Policy File Structure](#policy-file-structure)


ZPU is only needed to support decentralized authorization.
The policy updater is the utility that retrieves from ZTS
the policy files for provisioned domains on a host, which ZPE uses to
evaluate access requests. The ZPE library automatically parses
the policy file, validates it, and uses it for authorization
checks.

This document describes the format and how to validate the policy
file.

## Policy File Signature Validation
--------------------------------------

The policy file data which is provided in json format is signed
by both ZMS and ZTS servers since ZMS is the authority on policy
data but the file is downloaded from ZTS servers.

### ZTS Signature Validation
----------------------------

To validate the ZTS signature, the json is presented in the
following structure:

`{"signedPolicyData":<zts-data>,"keyId":"<key-id>,"signature":"<signature>"}`

a) Extract the `<key-id>` and fetch the public key with that key identifier from
Athenz for service `zts` in domain `sys.auth`.

For example, using `zms-cli` command line utility:

```
$ zms-cli -d sys.auth show-public-key zts zts1.0
public-key:
    keyID: zts1.0
    value: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V...WS0tLS0tCg--
```

The public key is encoded in YBase64 encoding so it must be decoded
before the public key can be used to validate the signature.

Checkout [YBase64](https://github.com/AthenZ/athenz/blob/master/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/util/YBase64.java) class implemenation in `athenz-auth-core` library for details.

b) Validate the signature of the extracted `<zts-data>` string using Bouncycastle.
`<signature>` field is also YBase64 encoded, so it must be decoded before
using in the verify function.

    1) Load the public key retrieved in step (a) and generate a PublicKey object.
    2) Generate the signature algorithm based on the public key algorithm. ZTS
    server is using SHA256 digest algorithm with either RSA or ECSDA keys so the
    possible values are either RSA_SHA256 or ECDSA_SHA256.
    3) Generate a signer and verify the signature (include proper exception handling):
        java.security.Signature signer = java.security.Signature.getInstance(signatureAlgorithm, BC_PROVIDER);
        signer.initVerify(publicKey);
        signer.update(utf8Bytes(ztsData));
        boolean valid = signer.verify(signature);

### ZMS Signature Validation
----------------------------

To validate the ZMS signature, we need to further parse the `<zts-data>`
object we retrieved in the ZTS Signture validation section. That json has
the following structure:

`{"expires":"<expiry-date>","modified":"<modified-date>","policyData":<zms-data>,"zmsKeyId":"<key-id>,"zmsSignature":"<signature>"}`

a) Extract the `<key-id>` and fetch the public key with that key identifier from
Athenz for service `zms` in domain `sys.auth`.

For example, using `zms-cli` command line utility:

```
$ zms-cli -d sys.auth show-public-key zms zms1.0
public-key:
    keyID: zms1.0
    value: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V...WS0tLS0tCg--
```

The public key is encoded in YBase64 encoding so it must be decoded
before the public key can be used to validate the signature.

Checkout [YBase64](https://github.com/AthenZ/athenz/blob/master/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/util/YBase64.java) class implemenation in `athenz-auth-core` library for details.

b) Validate the signature of the extracted `<zms-data>` string using Bouncycastle.
`<signature>` field is also YBase64 encoded, so it must be decoded before
using in the verify function.

    1) Load the public key retrieved in step (a) and generate a PublicKey object.
    2) Generate the signature algorithm based on the public key algorithm. ZMS
    server is using SHA256 digest algorithm with either RSA or ECSDA keys so the
    possible values are either RSA_SHA256 or ECDSA_SHA256.
    3) Generate a signer and verify the signature (include proper exception handling):
        java.security.Signature signer = java.security.Signature.getInstance(signatureAlgorithm, BC_PROVIDER);
        signer.initVerify(publicKey);
        signer.update(utf8Bytes(zmsData));
        boolean valid = signer.verify(signature);

## Policy File Structure
------------------------

Athenz Services are using RDL to represent its objects. These should directly
map to json objects:

```
type DomainSignedPolicyData Struct {
    SignedPolicyData signedPolicyData; //policy data signed by ZMS
    String signature; //signature generated based on the domain policies object
    String keyId; //the identifier of the key used to generate the signature
}

type SignedPolicyData Struct {
    PolicyData policyData; //list of policies defined in a domain
    String zmsSignature; //zms signature generated based on the domain policies object
    String zmsKeyId; //the identifier of the zms key used to generate the signature
    Timestamp modified; //when the domain itself was last modified
    Timestamp expires; //timestamp specifying the expiration time for using this set of policies
}

type PolicyData Struct {
    DomainName domain; //name of the domain
    Array<Policy> policies; //list of policies defined in this server
}

type Policy Struct {
    ResourceName name; //name of the policy
    Timestamp modified (optional); //last modification timestamp of this policy
    Array<Assertion> assertions; //list of defined assertions for this policy
}

type Assertion Struct {
    String role; //the subject of the assertion, a role
    String resource; //the object of the assertion. Must be in the local namespace. Can contain wildcards
    String action; //the predicate of the assertion. Can contain wildcards
    AssertionEffect effect (optional, default=ALLOW); //the effect of the assertion in the policy language
    Int64 id (optional); //assertion id - auto generated by server
}

type AssertionEffect Enum { ALLOW, DENY }
```

`DomainName` and `ResourceName` reference regular Strings. The zts java model classes
are available in the `athenz-zts-core` library.

```
  <dependencies>
    <dependency>
      <groupId>com.yahoo.athenz</groupId>
      <artifactId>athenz-zts-core</artifactId>
      <version>1.7.51</version>
    </dependency>
  </dependencies>
```
