// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package test_data

const Domain2Policies = `{
"signedPolicyData": {
"modified": "2015-01-13T19:13:37.745Z",
"policyData": {
"domain": "sys.auth",
"policies": [
{
"name": "sys.auth:policy.admin",
"assertions": [
{
"resource": "*",
"role": "sys.auth:role.admin",
"action": "*",
"effect": "ALLOW"
},
{
"resource": "*",
"role": "sys.auth:role.non-admin",
"action": "*",
"effect": "DENY"
}
]
}
]
},
"expires": "2015-01-20T19:13:37.744Z",
"zmsSignature": "eN5aZiqCof3HjHctjkYB2itNvI.90u.bq6zzLoXG8CJ8hSwG6IBMaIQ0yf.Q_SR5HTFi7Tmrc1quQuH17H0PJg--",
"zmsKeyId": "0"
},
"signature": "eN5aZiqCof3HjHctjkYB2itNvI.90u.bq6zzLoXG8CJ8hSwG6IBMaIQ0yf.Q_SR5HTFi7Tmrc1quQuH17H0PJg--",
"keyId": "0"
}`
