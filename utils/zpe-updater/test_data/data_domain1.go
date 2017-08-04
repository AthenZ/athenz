// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package test_data

const Domain1Policies = `
{
  "signedPolicyData": {
    "policyData": {
      "domain": "sys.auth",
      "policies": [
        {
          "name": "sys.auth:policy.admin",
          "assertions": [
            {
              "role": "sys.auth:role.admin",
              "resource": "*",
              "action": "*",
              "effect": "ALLOW"
            },
            {
              "role": "sys.auth:role.non-admin",
              "resource": "*",
              "action": "*",
              "effect": "DENY"
            }
          ]
        }
      ]
    },
    "zmsSignature": "Y2HuXmgL86PL1WnleGFHwPmNEqUdWgDxmmIsDnF5f5oqakacqTtwt9JNqDV9nuJ7LnKl3zsZoDQSAtcHMu4IGA--",
    "zmsKeyId": "0",
    "modified": "2017-06-02T06:11:12.125Z",
    "expires": "2017-06-09T06:11:12.125Z"
  },
  "signature": "XJnQ4t33D4yr7NtUjLaWhXULFr76z.z0p3QV4uCkA5KR9L4liVRmICYwVmnXxvHAlImKlKLv7sbIHNsjBfGfCw--",
  "keyId": "0"
}`
