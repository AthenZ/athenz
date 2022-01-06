var zmsspec = {
  "openapi" : "3.0.1",
  "info" : {
    "title" : "ZMS Swagger",
    "version" : "1.0.0"
  },
  "servers" : [ {
    "url" : "/v1/api"
  } ],
  "paths" : {
    "/v1/domain/{domainName}/policy/{policyName}/assertion/{assertionId}" : {
      "get" : {
        "description" : "Get the assertion details with specified id in the given policy",
        "operationId" : "getAssertion",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "assertionId",
          "in" : "path",
          "description" : "assertion id",
          "required" : true,
          "schema" : {
            "type" : "integer",
            "format" : "int64"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Assertion"
                }
              }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the specified policy assertion. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteAssertion",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "assertionId",
          "in" : "path",
          "description" : "assertion id",
          "required" : true,
          "schema" : {
            "type" : "integer",
            "format" : "int64"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy/{policyName}/assertion/{assertionId}/condition/{conditionId}" : {
      "delete" : {
        "description" : "Delete the assertion condition(s) for specified assertion id and condition id. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteAssertionCondition",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "assertionId",
          "in" : "path",
          "description" : "assertion id",
          "required" : true,
          "schema" : {
            "type" : "integer",
            "format" : "int64"
          }
        }, {
          "name" : "conditionId",
          "in" : "path",
          "description" : "condition id",
          "required" : true,
          "schema" : {
            "type" : "integer",
            "format" : "int32"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy/{policyName}/assertion/{assertionId}/conditions" : {
      "put" : {
        "description" : "Add the specified conditions to the given assertion",
        "operationId" : "putAssertionConditions",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "assertionId",
          "in" : "path",
          "description" : "assertion id",
          "required" : true,
          "schema" : {
            "type" : "integer",
            "format" : "int64"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Assertion conditions object to be added to the given assertion",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/AssertionConditions"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/AssertionConditions"
                }
              }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete all assertion conditions for specified assertion id. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteAssertionConditions",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "assertionId",
          "in" : "path",
          "description" : "assertion id",
          "required" : true,
          "schema" : {
            "type" : "integer",
            "format" : "int64"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy/{policyName}/version/{version}/assertion/{assertionId}" : {
      "delete" : {
        "description" : "Delete the specified policy version assertion. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteAssertionPolicyVersion",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "version",
          "in" : "path",
          "description" : "name of the version",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "assertionId",
          "in" : "path",
          "description" : "assertion id",
          "required" : true,
          "schema" : {
            "type" : "integer",
            "format" : "int64"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/member/{memberName}" : {
      "delete" : {
        "description" : "Delete the specified role member from the given domain. This command will remove the member from all the roles in the domain that it's member of. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteDomainRoleMember",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "memberName",
          "in" : "path",
          "description" : "name of the role member/principal",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit reference",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{name}/template/{template}" : {
      "put" : {
        "description" : "Update the given domain by applying the roles and policies defined in the specified solution template(s). Caller must have UPDATE privileges on the domain itself.",
        "operationId" : "putDomainTemplateExt",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain to be updated",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "template",
          "in" : "path",
          "description" : "name of the solution template",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "DomainTemplate object with a single template name to match URI",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/DomainTemplate"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      },
      "delete" : {
        "description" : "Update the given domain by deleting the specified template from the domain template list. Cycles through the roles and policies defined in the template and deletes them. Caller must have delete privileges on the domain itself.",
        "operationId" : "deleteDomainTemplate",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain to be updated",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "template",
          "in" : "path",
          "description" : "name of the solution template",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/entity/{entityName}" : {
      "get" : {
        "description" : "Get a entity from a domain. open for all authenticated users to read",
        "operationId" : "getEntity",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "entityName",
          "in" : "path",
          "description" : "name of entity",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Entity"
                }
              }
            }
          }
        }
      },
      "put" : {
        "description" : "Put an entity into the domain.",
        "operationId" : "putEntity",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "entityName",
          "in" : "path",
          "description" : "name of entity",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Entity object to be added to the domain",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Entity"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the entity from the domain. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteEntity",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "entityName",
          "in" : "path",
          "description" : "name of entity",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/group/{groupName}" : {
      "get" : {
        "description" : "Get the specified group in the domain.",
        "operationId" : "getGroup",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "groupName",
          "in" : "path",
          "description" : "name of the group to be retrieved",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "auditLog",
          "in" : "query",
          "description" : "flag to indicate whether or not to return group audit log",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        }, {
          "name" : "pending",
          "in" : "query",
          "description" : "include pending members",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Group"
                }
              }
            }
          }
        }
      },
      "put" : {
        "description" : "Create/update the specified group.",
        "operationId" : "putGroup",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "groupName",
          "in" : "path",
          "description" : "name of the group to be added/updated",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Group object to be added/updated in the domain",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Group"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the specified group. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteGroup",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "groupName",
          "in" : "path",
          "description" : "name of the group to be deleted",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/group/{groupName}/member/{memberName}" : {
      "get" : {
        "description" : "Get the membership status for a specified user in a group.",
        "operationId" : "getGroupMembership",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "groupName",
          "in" : "path",
          "description" : "name of the group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "memberName",
          "in" : "path",
          "description" : "user name to be checked for membership",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "expiration",
          "in" : "query",
          "description" : "the expiration timestamp",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/GroupMembership"
                }
              }
            }
          }
        }
      },
      "put" : {
        "description" : "Add the specified user to the group's member list. If the group is neither auditEnabled nor selfserve, then it will use authorize (\"update\", \"{domainName}:group.{groupName}\") otherwise membership will be sent for approval to either designated delegates ( in case of auditEnabled groups ) or to domain admins ( in case of selfserve groups )",
        "operationId" : "putGroupMembership",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "groupName",
          "in" : "path",
          "description" : "name of the group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "memberName",
          "in" : "path",
          "description" : "name of the user to be added as a member",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Membership object (must contain group/member names as specified in the URI)",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/GroupMembership"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the specified group membership. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteGroupMembership",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "groupName",
          "in" : "path",
          "description" : "name of the group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "memberName",
          "in" : "path",
          "description" : "name of the user to be removed as a member",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/role/{roleName}/member/{memberName}" : {
      "get" : {
        "description" : "Get the membership status for a specified user in a role.",
        "operationId" : "getMembership",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of the role",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "memberName",
          "in" : "path",
          "description" : "user name to be checked for membership",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "expiration",
          "in" : "query",
          "description" : "the expiration timestamp",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Membership"
                }
              }
            }
          }
        }
      },
      "put" : {
        "description" : "Add the specified user to the role's member list. If the role is neither auditEnabled nor selfserve, then it will use authorize (\"update\", \"{domainName}:role.{roleName}\") or (\"update_members\", \"{domainName}:role.{roleName}\"). This only allows access to members and not role attributes. otherwise membership will be sent for approval to either designated delegates ( in case of auditEnabled roles ) or to domain admins ( in case of selfserve roles )",
        "operationId" : "putMembership",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of the role",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "memberName",
          "in" : "path",
          "description" : "name of the user to be added as a member",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Membership object (must contain role/member names as specified in the URI)",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Membership"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the specified role membership. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned). The required authorization includes two options: (\"update\", \"{domainName}:role.{roleName}\") or (\"update_members\", \"{domainName}:role.{roleName}\")",
        "operationId" : "deleteMembership",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of the role",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "memberName",
          "in" : "path",
          "description" : "name of the user to be removed as a member",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/group/{groupName}/pendingmember/{memberName}" : {
      "delete" : {
        "description" : "Delete the specified pending group membership. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned). Authorization will be completed within the server itself since there are two possibilities: 1) The domain admins can delete any pending requests 2) the requestor can also delete his/her own pending request.",
        "operationId" : "deletePendingGroupMembership",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "groupName",
          "in" : "path",
          "description" : "name of the group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "memberName",
          "in" : "path",
          "description" : "name of the user to be removed as a pending member",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/role/{roleName}/pendingmember/{memberName}" : {
      "delete" : {
        "description" : "Delete the specified pending role membership. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned). Authorization will be completed within the server itself since there are two possibilities: 1) The domain admins can delete any pending requests 2) the requestor can also delete his/her own pending request.",
        "operationId" : "deletePendingMembership",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of the role",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "memberName",
          "in" : "path",
          "description" : "name of the user to be removed as a pending member",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy/{policyName}" : {
      "get" : {
        "description" : "Read the specified policy.",
        "operationId" : "getPolicy",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy to be retrieved",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Policy"
                }
              }
            }
          }
        }
      },
      "put" : {
        "description" : "Create or update the specified policy.",
        "operationId" : "putPolicy",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy to be added/updated",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Policy object to be added or updated in the domain",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Policy"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the specified policy. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deletePolicy",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy to be deleted",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy/{policyName}/version/{version}" : {
      "get" : {
        "description" : "Get the specified policy version.",
        "operationId" : "getPolicyVersion",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "version",
          "in" : "path",
          "description" : "name of the version to be retrieved",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Policy"
                }
              }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the specified policy version. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deletePolicyVersion",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "version",
          "in" : "path",
          "description" : "name of the version to be deleted",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{tenantDomain}/provDomain/{provDomain}/provService/{provService}/resourceGroup/{resourceGroup}" : {
      "get" : {
        "description" : "Retrieve the configured set of roles for the provider and resource group",
        "operationId" : "getProviderResourceGroupRoles",
        "parameters" : [ {
          "name" : "tenantDomain",
          "in" : "path",
          "description" : "name of the tenant domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "provDomain",
          "in" : "path",
          "description" : "name of the provider domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "provService",
          "in" : "path",
          "description" : "name of the provider service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "resourceGroup",
          "in" : "path",
          "description" : "tenant resource group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/ProviderResourceGroupRoles"
                }
              }
            }
          }
        }
      },
      "put" : {
        "description" : "Create/update set of roles for a given provider and resource group",
        "operationId" : "putProviderResourceGroupRoles",
        "parameters" : [ {
          "name" : "tenantDomain",
          "in" : "path",
          "description" : "name of the tenant domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "provDomain",
          "in" : "path",
          "description" : "name of the provider domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "provService",
          "in" : "path",
          "description" : "name of the provider service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "resourceGroup",
          "in" : "path",
          "description" : "tenant resource group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "list of roles to be added/updated for the provider",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/ProviderResourceGroupRoles"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/ProviderResourceGroupRoles"
                }
              }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the configured set of roles for the provider and resource group",
        "operationId" : "deleteProviderResourceGroupRoles",
        "parameters" : [ {
          "name" : "tenantDomain",
          "in" : "path",
          "description" : "name of the tenant domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "provDomain",
          "in" : "path",
          "description" : "name of the provider domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "provService",
          "in" : "path",
          "description" : "name of the provider service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "resourceGroup",
          "in" : "path",
          "description" : "tenant resource group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domain}/service/{service}/publickey/{id}" : {
      "get" : {
        "description" : "Retrieve the specified public key from the service.",
        "operationId" : "getPublicKeyEntry",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "id",
          "in" : "path",
          "description" : "the identifier of the public key to be retrieved",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/PublicKeyEntry"
                }
              }
            }
          }
        }
      },
      "put" : {
        "description" : "Add the specified public key to the service.",
        "operationId" : "putPublicKeyEntry",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "id",
          "in" : "path",
          "description" : "the identifier of the public key to be added",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "PublicKeyEntry object to be added/updated in the service",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/PublicKeyEntry"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      },
      "delete" : {
        "description" : "Remove the specified public key from the service. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deletePublicKeyEntry",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "id",
          "in" : "path",
          "description" : "the identifier of the public key to be deleted",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{name}/quota" : {
      "get" : {
        "description" : "Retrieve the quota object defined for the domain",
        "operationId" : "getQuota",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Quota"
                }
              }
            }
          }
        }
      },
      "put" : {
        "description" : "Update the specified domain's quota object",
        "operationId" : "putQuota",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit reference",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Quota object with limits for the domain",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Quota"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the specified domain's quota",
        "operationId" : "deleteQuota",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit reference",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/role/{roleName}" : {
      "get" : {
        "description" : "Get the specified role in the domain.",
        "operationId" : "getRole",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of the role to be retrieved",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "auditLog",
          "in" : "query",
          "description" : "flag to indicate whether or not to return role audit log",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        }, {
          "name" : "expand",
          "in" : "query",
          "description" : "expand delegated trust roles and return trusted members",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        }, {
          "name" : "pending",
          "in" : "query",
          "description" : "include pending members",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Role"
                }
              }
            }
          }
        }
      },
      "put" : {
        "description" : "Create/update the specified role.",
        "operationId" : "putRole",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of the role to be added/updated",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Role object to be added/updated in the domain",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Role"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the specified role. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteRole",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of the role to be deleted",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domain}/service/{service}" : {
      "get" : {
        "description" : "Get info for the specified ServiceIdentity.",
        "operationId" : "getServiceIdentity",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the service to be retrieved",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/ServiceIdentity"
                }
              }
            }
          }
        }
      },
      "put" : {
        "description" : "Register the specified ServiceIdentity in the specified domain",
        "operationId" : "putServiceIdentity",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "ServiceIdentity object to be added/updated in the domain",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/ServiceIdentity"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the specified ServiceIdentity. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteServiceIdentity",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the service to be deleted",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/subdomain/{parent}/{name}" : {
      "delete" : {
        "description" : "Delete the specified subdomain. Caller must have domain delete permissions in parent. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteSubDomain",
        "parameters" : [ {
          "name" : "parent",
          "in" : "path",
          "description" : "name of the parent domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "name",
          "in" : "path",
          "description" : "name of the subdomain to be deleted",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domain}/tenancy/{service}" : {
      "put" : {
        "description" : "Register the provider service in the tenant's domain.",
        "operationId" : "putTenancy",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the tenant domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the provider service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "tenancy object",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Tenancy"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the provider service from the specified tenant domain. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteTenancy",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the tenant domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the provider service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domain}/service/{service}/tenant/{tenantDomain}" : {
      "put" : {
        "description" : "Register a tenant domain for given provider service",
        "operationId" : "putTenant",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the provider domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the provider service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "tenantDomain",
          "in" : "path",
          "description" : "name of the tenant domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "tenancy object",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Tenancy"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the tenant domain from the provider service. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteTenant",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the provider domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the provider service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "tenantDomain",
          "in" : "path",
          "description" : "name of the tenant domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domain}/service/{service}/tenant/{tenantDomain}/resourceGroup/{resourceGroup}" : {
      "get" : {
        "description" : "Retrieve the configured set of roles for the tenant and resource group",
        "operationId" : "getTenantResourceGroupRoles",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the provider domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the provider service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "tenantDomain",
          "in" : "path",
          "description" : "name of the tenant domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "resourceGroup",
          "in" : "path",
          "description" : "tenant resource group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/TenantResourceGroupRoles"
                }
              }
            }
          }
        }
      },
      "put" : {
        "description" : "Create/update set of roles for a given tenant and resource group",
        "operationId" : "putTenantResourceGroupRoles",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the provider domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the provider service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "tenantDomain",
          "in" : "path",
          "description" : "name of the tenant domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "resourceGroup",
          "in" : "path",
          "description" : "tenant resource group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "list of roles to be added/updated for the tenant",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/TenantResourceGroupRoles"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/TenantResourceGroupRoles"
                }
              }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the configured set of roles for the tenant and resource group",
        "operationId" : "deleteTenantResourceGroupRoles",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the provider domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the provider service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "tenantDomain",
          "in" : "path",
          "description" : "name of the tenant domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "resourceGroup",
          "in" : "path",
          "description" : "tenant resource group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{name}" : {
      "delete" : {
        "description" : "Delete the specified domain.  This is a privileged action for the \"sys.auth\" administrators. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteTopLevelDomain",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain to be deleted",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/user/{name}" : {
      "delete" : {
        "description" : "Delete the specified user. This command will delete the home.<name> domain and all of its sub-domains (if they exist) and remove the user.<name> from all the roles in the system that it's member of. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteUser",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the user",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit reference",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/userdomain/{name}" : {
      "post" : {
        "description" : "Create a new user domain. The user domain will be created in the user top level domain and the user himself will be set as the administrator for this domain.",
        "operationId" : "postUserDomain",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain which will be the user id",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "UserDomain object to be created",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/UserDomain"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Domain"
                }
              }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the specified userdomain. Caller must have domain delete permissions in the domain. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).",
        "operationId" : "deleteUserDomain",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain to be deleted which will be the user id",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/access/{action}/{resource}" : {
      "get" : {
        "description" : "Check access for the specified operation on the specified resource for the currently authenticated user. This is the slow centralized access for control-plane purposes. Use distributed mechanisms for decentralized (data-plane) access by fetching signed policies and role tokens for users. With this endpoint the resource is part of the uri and restricted to its strict definition of resource name. If needed, you can use the GetAccessExt api that allows resource name to be less restrictive.",
        "operationId" : "getAccess",
        "parameters" : [ {
          "name" : "action",
          "in" : "path",
          "description" : "action as specified in the policy assertion, i.e. update or read",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "resource",
          "in" : "path",
          "description" : "the resource to check access against, i.e. \"media.news:articles\"",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "domain",
          "in" : "query",
          "description" : "usually null. If present, it specifies an alternate domain for cross-domain trust relation",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "principal",
          "in" : "query",
          "description" : "usually null. If present, carry out the access check for this principal",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Access"
                }
              }
            }
          }
        }
      }
    },
    "/v1/access/{action}" : {
      "get" : {
        "description" : "Check access for the specified operation on the specified resource for the currently authenticated user. This is the slow centralized access for control-plane purposes.",
        "operationId" : "getAccessExt",
        "parameters" : [ {
          "name" : "action",
          "in" : "path",
          "description" : "action as specified in the policy assertion, i.e. update or read",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "resource",
          "in" : "query",
          "description" : "the resource to check access against, i.e. \"media.news:articles\"",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "domain",
          "in" : "query",
          "description" : "usually null. If present, it specifies an alternate domain for cross-domain trust relation",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "principal",
          "in" : "query",
          "description" : "usually null. If present, carry out the access check for this principal",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Access"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domain}" : {
      "get" : {
        "description" : "Get info for the specified domain, by name. This request only returns the configured domain attributes and not any domain objects like roles, policies or service identities.",
        "operationId" : "getDomain",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Domain"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/check" : {
      "get" : {
        "description" : "Carry out data check operation for the specified domain.",
        "operationId" : "getDomainDataCheck",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/DomainDataCheck"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain" : {
      "get" : {
        "description" : "Enumerate domains. Can be filtered by prefix and depth, and paginated. Most of the query options that are looking for specific domain attributes (e.g. aws account, azure subscriptions, business service, tags, etc) are mutually exclusive. The server will only process the first query argument and ignore the others.",
        "operationId" : "getDomainList",
        "parameters" : [ {
          "name" : "limit",
          "in" : "query",
          "description" : "restrict the number of results in this call",
          "schema" : {
            "type" : "integer",
            "format" : "int32"
          }
        }, {
          "name" : "skip",
          "in" : "query",
          "description" : "restrict the set to those after the specified \"next\" token returned from a previous call",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "prefix",
          "in" : "query",
          "description" : "restrict to names that start with the prefix",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "depth",
          "in" : "query",
          "description" : "restrict the depth of the name, specifying the number of '.' characters that can appear",
          "schema" : {
            "type" : "integer",
            "format" : "int32"
          }
        }, {
          "name" : "account",
          "in" : "query",
          "description" : "restrict to domain names that have specified account name",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "ypmid",
          "in" : "query",
          "description" : "restrict the domain names that have specified product id",
          "schema" : {
            "type" : "integer",
            "format" : "int32"
          }
        }, {
          "name" : "member",
          "in" : "query",
          "description" : "restrict the domain names where the specified user is in a role - see roleName",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "role",
          "in" : "query",
          "description" : "restrict the domain names where the specified user is in this role - see roleMember",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "azure",
          "in" : "query",
          "description" : "restrict to domain names that have specified azure subscription name",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "tagKey",
          "in" : "query",
          "description" : "flag to query all domains that have a given tagName",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "tagValue",
          "in" : "query",
          "description" : "flag to query all domains that have a given tag name and value",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "businessService",
          "in" : "query",
          "description" : "restrict to domain names that have specified business service name",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "If-Modified-Since",
          "in" : "header",
          "description" : "This header specifies to the server to return any domains modified since this HTTP date",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/DomainList"
                }
              }
            }
          }
        }
      },
      "post" : {
        "description" : "Create a new top level domain. This is a privileged action for the \"sys.auth\" administrators.",
        "operationId" : "postTopLevelDomain",
        "parameters" : [ {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "TopLevelDomain object to be created",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/TopLevelDomain"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Domain"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/metastore" : {
      "get" : {
        "description" : "List all valid values for the given attribute and user",
        "operationId" : "getDomainMetaStoreValidValuesList",
        "parameters" : [ {
          "name" : "attribute",
          "in" : "query",
          "description" : "name of attribute",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "user",
          "in" : "query",
          "description" : "restrict to values associated with the given user",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/DomainMetaStoreValidValuesList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/member" : {
      "get" : {
        "description" : "Get list of principals defined in roles in the given domain",
        "operationId" : "getDomainRoleMembers",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/DomainRoleMembers"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{name}/templatedetails" : {
      "get" : {
        "description" : "Get a list of Solution templates with meta data details given a domain name",
        "operationId" : "getDomainTemplateDetailsList",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "List of templates given a domain name",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/DomainTemplateDetailsList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{name}/template" : {
      "get" : {
        "description" : "Get the list of solution templates applied to a domain",
        "operationId" : "getDomainTemplateList",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/DomainTemplateList"
                }
              }
            }
          }
        }
      },
      "put" : {
        "description" : "Update the given domain by applying the roles and policies defined in the specified solution template(s). Caller must have UPDATE privileges on the domain itself.",
        "operationId" : "putDomainTemplate",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain to be updated",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "DomainTemplate object with solution template name(s)",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/DomainTemplate"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/entity" : {
      "get" : {
        "description" : "Enumerate entities provisioned in this domain.",
        "operationId" : "getEntityList",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/EntityList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/groups" : {
      "get" : {
        "description" : "Get the list of all groups in a domain with optional flag whether or not include members",
        "operationId" : "getGroups",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "members",
          "in" : "query",
          "description" : "return list of members in the group",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        }, {
          "name" : "tagKey",
          "in" : "query",
          "description" : "flag to query all groups that have a given tagName",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "tagValue",
          "in" : "query",
          "description" : "flag to query all groups that have a given tag name and value",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Groups"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{name}/signed" : {
      "get" : {
        "operationId" : "getJWSDomain",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain to be retrieved",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "signaturep1363format",
          "in" : "query",
          "description" : "true if signature must be in P1363 format instead of ASN.1 DER",
          "schema" : {
            "type" : "boolean"
          }
        }, {
          "name" : "If-None-Match",
          "in" : "header",
          "description" : "Retrieved from the previous request, this timestamp specifies to the server to return if the domain was modified since this time",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/overdue" : {
      "get" : {
        "description" : "Get members with overdue review",
        "operationId" : "getOverdueReview",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/DomainRoleMembers"
                }
              }
            }
          }
        }
      }
    },
    "/v1/pending_group_members" : {
      "get" : {
        "description" : "List of domains containing groups and corresponding members to be approved by either calling or specified principal",
        "operationId" : "getPendingDomainGroupMembersList",
        "parameters" : [ {
          "name" : "principal",
          "in" : "query",
          "description" : "If present, return pending list for this principal",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/DomainGroupMembership"
                }
              }
            }
          }
        }
      }
    },
    "/v1/pending_members" : {
      "get" : {
        "description" : "List of domains containing roles and corresponding members to be approved by either calling or specified principal",
        "operationId" : "getPendingDomainRoleMembersList",
        "parameters" : [ {
          "name" : "principal",
          "in" : "query",
          "description" : "If present, return pending list for this principal",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/DomainRoleMembership"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policies" : {
      "get" : {
        "description" : "List policies provisioned in this namespace.",
        "operationId" : "getPolicies",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "assertions",
          "in" : "query",
          "description" : "return list of assertions in the policy",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        }, {
          "name" : "includeNonActive",
          "in" : "query",
          "description" : "include non-active policy versions",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Policies"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy" : {
      "get" : {
        "description" : "List policies provisioned in this namespace.",
        "operationId" : "getPolicyList",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "limit",
          "in" : "query",
          "description" : "restrict the number of results in this call",
          "schema" : {
            "type" : "integer",
            "format" : "int32"
          }
        }, {
          "name" : "skip",
          "in" : "query",
          "description" : "restrict the set to those after the specified \"next\" token returned from a previous call",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/PolicyList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy/{policyName}/version" : {
      "get" : {
        "description" : "List policy versions.",
        "operationId" : "getPolicyVersionList",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/PolicyList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/group" : {
      "get" : {
        "description" : "Fetch all the groups across domains by either calling or specified principal",
        "operationId" : "getPrincipalGroups",
        "parameters" : [ {
          "name" : "principal",
          "in" : "query",
          "description" : "If not present, will return groups for the user making the call",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "domain",
          "in" : "query",
          "description" : "If not present, will return groups from all domains",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/DomainGroupMember"
                }
              }
            }
          }
        }
      }
    },
    "/v1/role" : {
      "get" : {
        "description" : "Fetch all the roles across domains by either calling or specified principal",
        "operationId" : "getPrincipalRoles",
        "parameters" : [ {
          "name" : "principal",
          "in" : "query",
          "description" : "If not present, will return roles for the user making the call",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "domain",
          "in" : "query",
          "description" : "If not present, will return roles from all domains",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/DomainRoleMember"
                }
              }
            }
          }
        }
      }
    },
    "/v1/schema" : {
      "get" : {
        "description" : "Get RDL Schema",
        "operationId" : "getRdlSchema",
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Schema"
                }
              }
            }
          }
        }
      }
    },
    "/v1/resource" : {
      "get" : {
        "description" : "Return list of resources that the given principal has access to. Even though the principal is marked as optional, it must be specified",
        "operationId" : "getResourceAccessList",
        "parameters" : [ {
          "name" : "principal",
          "in" : "query",
          "description" : "specifies principal to query the resource list for",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "action",
          "in" : "query",
          "description" : "action as specified in the policy assertion",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/ResourceAccessList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/role" : {
      "get" : {
        "description" : "Enumerate roles provisioned in this domain.",
        "operationId" : "getRoleList",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "limit",
          "in" : "query",
          "description" : "restrict the number of results in this call",
          "schema" : {
            "type" : "integer",
            "format" : "int32"
          }
        }, {
          "name" : "skip",
          "in" : "query",
          "description" : "restrict the set to those after the specified \"next\" token returned from a previous call",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/RoleList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/roles" : {
      "get" : {
        "description" : "Get the list of all roles in a domain with optional flag whether or not include members",
        "operationId" : "getRoles",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "members",
          "in" : "query",
          "description" : "return list of members in the role",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        }, {
          "name" : "tagKey",
          "in" : "query",
          "description" : "flag to query all roles that have a given tagName",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "tagValue",
          "in" : "query",
          "description" : "flag to query all roles that have a given tag name and value",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Roles"
                }
              }
            }
          }
        }
      }
    },
    "/v1/templatedetails" : {
      "get" : {
        "description" : "Get a list of Solution templates with meta data details defined in the server",
        "operationId" : "getServerTemplateDetailsList",
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/DomainTemplateDetailsList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/template" : {
      "get" : {
        "description" : "Get the list of solution templates defined in the server",
        "operationId" : "getServerTemplateList",
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/ServerTemplateList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/services" : {
      "get" : {
        "description" : "Retrieve list of service identities",
        "operationId" : "getServiceIdentities",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "publickeys",
          "in" : "query",
          "description" : "return list of public keys in the service",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        }, {
          "name" : "hosts",
          "in" : "query",
          "description" : "return list of hosts in the service",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/ServiceIdentities"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/service" : {
      "get" : {
        "description" : "Enumerate services provisioned in this domain.",
        "operationId" : "getServiceIdentityList",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "limit",
          "in" : "query",
          "description" : "restrict the number of results in this call",
          "schema" : {
            "type" : "integer",
            "format" : "int32"
          }
        }, {
          "name" : "skip",
          "in" : "query",
          "description" : "restrict the set to those after the specified \"next\" token returned from a previous call",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/ServiceIdentityList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/principal" : {
      "get" : {
        "description" : "Return a ServicePrincipal object if the serviceToken is valid. This request provides a simple operation that an external application can execute to validate a service token.",
        "operationId" : "getServicePrincipal",
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/ServicePrincipal"
                }
              }
            }
          }
        }
      }
    },
    "/v1/sys/modified_domains" : {
      "get" : {
        "description" : "Retrieve the list of modified domains since the specified timestamp. The server will return the list of all modified domains and the latest modification timestamp as the value of the ETag header. The client will need to use this value during its next call to request the changes since the previous request. When metaonly set to true, don't add roles, policies or services, don't sign",
        "operationId" : "getSignedDomains",
        "parameters" : [ {
          "name" : "domain",
          "in" : "query",
          "description" : "filter the domain list only to the specified name",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "metaonly",
          "in" : "query",
          "description" : "valid values are \"true\" or \"false\"",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "metaattr",
          "in" : "query",
          "description" : "domain meta attribute to filter/return, valid values \"account\", \"ypmId\", or \"all\"",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "master",
          "in" : "query",
          "description" : "for system principals only - request data from master data store and not read replicas if any are configured",
          "schema" : {
            "type" : "boolean"
          }
        }, {
          "name" : "conditions",
          "in" : "query",
          "description" : "for specific purpose only. If this flag is passed, assertion id and assertion conditions will be included in the response assertions if available",
          "schema" : {
            "type" : "boolean"
          }
        }, {
          "name" : "If-None-Match",
          "in" : "header",
          "description" : "Retrieved from the previous request, this timestamp specifies to the server to return any domains modified since this time",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/status" : {
      "get" : {
        "description" : "Retrieve the server status",
        "operationId" : "getStatus",
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Status"
                }
              }
            }
          }
        }
      }
    },
    "/v1/template/{template}" : {
      "get" : {
        "description" : "Get solution template details. Includes the roles and policies that will be automatically provisioned when the template is applied to a domain",
        "operationId" : "getTemplate",
        "parameters" : [ {
          "name" : "template",
          "in" : "path",
          "description" : "name of the solution template",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Template"
                }
              }
            }
          }
        }
      }
    },
    "/v1/authority/user/attribute" : {
      "get" : {
        "description" : "Map of type to attribute values for the user authority",
        "operationId" : "getUserAuthorityAttributeMap",
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/UserAuthorityAttributeMap"
                }
              }
            }
          }
        }
      }
    },
    "/v1/user" : {
      "get" : {
        "description" : "Enumerate users that are registered as principals in the system This will return only the principals with \"<user-domain>.\" prefix",
        "operationId" : "getUserList",
        "parameters" : [ {
          "name" : "domain",
          "in" : "query",
          "description" : "name of the allowed user-domains and/or aliases",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/UserList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/user/{userName}/token" : {
      "get" : {
        "description" : "Return a user/principal token for the specified authenticated user. Typical authenticated users with their native credentials are not allowed to update their domain data. They must first obtain a UserToken and then use that token for authentication and authorization of their update requests.",
        "operationId" : "getUserToken",
        "parameters" : [ {
          "name" : "userName",
          "in" : "path",
          "description" : "name of the user",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "services",
          "in" : "query",
          "description" : "comma separated list of on-behalf-of service names",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "header",
          "in" : "query",
          "description" : "include Authorization header name in response",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/UserToken"
                }
              }
            }
          }
        }
      },
      "options" : {
        "description" : "CORS (Cross-Origin Resource Sharing) support to allow Provider Services to obtain AuthorizedService Tokens on behalf of Tenant administrators",
        "operationId" : "optionsUserToken",
        "parameters" : [ {
          "name" : "userName",
          "in" : "path",
          "description" : "name of the user",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "services",
          "in" : "query",
          "description" : "comma separated list of on-behalf-of service names",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "*/*" : {
                "schema" : {
                  "$ref" : "#/components/schemas/UserToken"
                }
              }
            }
          }
        }
      }
    },
    "/v1/subdomain/{parent}" : {
      "post" : {
        "description" : "Create a new subdomain. The domain administrators of the {parent} domain have the privilege to create subdomains.",
        "operationId" : "postSubDomain",
        "parameters" : [ {
          "name" : "parent",
          "in" : "path",
          "description" : "name of the parent domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Subdomain object to be created",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/SubDomain"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Domain"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy/{policyName}/assertion" : {
      "put" : {
        "description" : "Add the specified assertion to the given policy",
        "operationId" : "putAssertion",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Assertion object to be added to the given policy",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Assertion"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Assertion"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy/{policyName}/assertion/{assertionId}/condition" : {
      "put" : {
        "description" : "Add the specified condition to the existing assertion conditions of an assertion",
        "operationId" : "putAssertionCondition",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "assertionId",
          "in" : "path",
          "description" : "assertion id",
          "required" : true,
          "schema" : {
            "type" : "integer",
            "format" : "int64"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Assertion conditions object to be added to the given assertion",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/AssertionCondition"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/AssertionCondition"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy/{policyName}/version/{version}/assertion" : {
      "put" : {
        "description" : "Add the specified assertion to the given policy version",
        "operationId" : "putAssertionPolicyVersion",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "version",
          "in" : "path",
          "description" : "name of the version",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Assertion object to be added to the given policy version",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Assertion"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Assertion"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/admins" : {
      "put" : {
        "description" : "Verify and, if necessary, fix domain roles and policies to make sure the given set of users have administrative access to the domain. This request is only restricted to \"sys.auth\" domain administrators and can be used when the domain administrators incorrectly have blocked their own access to their domains.",
        "operationId" : "putDefaultAdmins",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "list of domain administrators",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/DefaultAdmins"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{name}/meta" : {
      "put" : {
        "description" : "Update the specified top level domain metadata. Note that entities in the domain are not affected. Caller must have update privileges on the domain itself.",
        "operationId" : "putDomainMeta",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain to be updated",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "DomainMeta object with updated attribute values",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/DomainMeta"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{name}/meta/system/{attribute}" : {
      "put" : {
        "description" : "Set the specified top level domain metadata. Note that entities in the domain are not affected. Caller must have update privileges on the domain itself. If the system attribute is one of the string attributes, then the caller must also have delete action on the same resource in order to reset the configured value",
        "operationId" : "putDomainSystemMeta",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the domain to be updated",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "attribute",
          "in" : "path",
          "description" : "name of the system attribute to be modified",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "DomainMeta object with updated attribute values",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/DomainMeta"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/group/{groupName}/member/{memberName}/decision" : {
      "put" : {
        "description" : "Approve or Reject the request to add specified user to group membership. This endpoint will be used by 2 use cases: 1. Audit enabled groups with authorize (\"update\", \"sys.auth:meta.group.{attribute}.{domainName}\") 2. Selfserve groups in any domain with authorize (\"update\", \"{domainName}:\")",
        "operationId" : "putGroupMembershipDecision",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "groupName",
          "in" : "path",
          "description" : "name of the group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "memberName",
          "in" : "path",
          "description" : "name of the user to be added as a member",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "GroupMembership object (must contain group/member names as specified in the URI)",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/GroupMembership"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/group/{groupName}/meta" : {
      "put" : {
        "description" : "Update the specified group metadata. Caller must have update privileges on the domain itself.",
        "operationId" : "putGroupMeta",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain to be updated",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "groupName",
          "in" : "path",
          "description" : "name of the group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "GroupMeta object with updated attribute values",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/GroupMeta"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/group/{groupName}/review" : {
      "put" : {
        "description" : "Review group membership and take action to either extend and/or delete existing members.",
        "operationId" : "putGroupReview",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "groupName",
          "in" : "path",
          "description" : "name of the group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Group object with updated and/or deleted members",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Group"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/group/{groupName}/meta/system/{attribute}" : {
      "put" : {
        "description" : "Set the specified group metadata. Caller must have update privileges on the sys.auth domain. If the system attribute is one of the string attributes, then the caller must also have delete action on the same resource in order to reset the configured value",
        "operationId" : "putGroupSystemMeta",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "groupName",
          "in" : "path",
          "description" : "name of the group",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "attribute",
          "in" : "path",
          "description" : "name of the system attribute to be modified",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "GroupSystemMeta object with updated attribute values",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/GroupSystemMeta"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/role/{roleName}/member/{memberName}/decision" : {
      "put" : {
        "description" : "Approve or Reject the request to add specified user to role membership. This endpoint will be used by 2 use cases: 1. Audit enabled roles with authorize (\"update\", \"sys.auth:meta.role.{attribute}.{domainName}\") 2. Selfserve roles in any domain with authorize (\"update\", \"{domainName}:\")",
        "operationId" : "putMembershipDecision",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of the role",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "memberName",
          "in" : "path",
          "description" : "name of the user to be added as a member",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Membership object (must contain role/member names as specified in the URI)",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Membership"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy/{policyName}/version/create" : {
      "put" : {
        "description" : "Create a new disabled policy version based on active policy",
        "operationId" : "putPolicyVersion",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy to be added/updated",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "name of the source version to copy from and name of new version",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/PolicyOptions"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/role/{roleName}/meta" : {
      "put" : {
        "description" : "Update the specified role metadata. Caller must have update privileges on the domain itself.",
        "operationId" : "putRoleMeta",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain to be updated",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of the role",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "RoleMeta object with updated attribute values",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/RoleMeta"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/role/{roleName}/review" : {
      "put" : {
        "description" : "Review role membership and take action to either extend and/or delete existing members.",
        "operationId" : "putRoleReview",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of the role",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "Role object with updated and/or deleted members",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/Role"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/role/{roleName}/meta/system/{attribute}" : {
      "put" : {
        "description" : "Set the specified role metadata. Caller must have update privileges on the sys.auth domain. If the system attribute is one of the string attributes, then the caller must also have delete action on the same resource in order to reset the configured value",
        "operationId" : "putRoleSystemMeta",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of the role",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "attribute",
          "in" : "path",
          "description" : "name of the system attribute to be modified",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "RoleSystemMeta object with updated attribute values",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/RoleSystemMeta"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domain}/service/{service}/meta/system/{attribute}" : {
      "put" : {
        "description" : "Set the specified service metadata. Caller must have update privileges on the sys.auth domain.",
        "operationId" : "putServiceIdentitySystemMeta",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "attribute",
          "in" : "path",
          "description" : "name of the system attribute to be modified",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "ServiceIdentitySystemMeta object with updated attribute values",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/ServiceIdentitySystemMeta"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy/{policyName}/version/active" : {
      "put" : {
        "description" : "Mark the specified policy version as active",
        "operationId" : "setActivePolicyVersion",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "policyName",
          "in" : "path",
          "description" : "name of the policy",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "Y-Audit-Ref",
          "in" : "header",
          "description" : "Audit param required(not empty) if domain auditEnabled is true.",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "name of the version",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/PolicyOptions"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/application.wadl/{path}" : {
      "get" : {
        "operationId" : "getExternalGrammar",
        "parameters" : [ {
          "name" : "path",
          "in" : "path",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/xml" : { }
            }
          }
        }
      }
    },
    "/application.wadl" : {
      "get" : {
        "operationId" : "getWadl",
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/vnd.sun.wadl+xml" : { },
              "application/xml" : { }
            }
          }
        }
      }
    }
  },
  "components" : {
    "schemas" : {
      "Access" : {
        "type" : "object",
        "properties" : {
          "granted" : {
            "type" : "boolean"
          }
        }
      },
      "Assertion" : {
        "type" : "object",
        "properties" : {
          "role" : {
            "type" : "string"
          },
          "resource" : {
            "type" : "string"
          },
          "action" : {
            "type" : "string"
          },
          "effect" : {
            "type" : "string",
            "enum" : [ "ALLOW", "DENY" ]
          },
          "id" : {
            "type" : "integer",
            "format" : "int64"
          },
          "caseSensitive" : {
            "type" : "boolean"
          },
          "conditions" : {
            "$ref" : "#/components/schemas/AssertionConditions"
          }
        }
      },
      "AssertionCondition" : {
        "type" : "object",
        "properties" : {
          "id" : {
            "type" : "integer",
            "format" : "int32"
          },
          "conditionsMap" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/AssertionConditionData"
            }
          }
        }
      },
      "AssertionConditionData" : {
        "type" : "object",
        "properties" : {
          "operator" : {
            "type" : "string",
            "enum" : [ "EQUALS" ]
          },
          "value" : {
            "type" : "string"
          }
        }
      },
      "AssertionConditions" : {
        "type" : "object",
        "properties" : {
          "conditionsList" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/AssertionCondition"
            }
          }
        }
      },
      "Domain" : {
        "type" : "object",
        "properties" : {
          "description" : {
            "type" : "string"
          },
          "org" : {
            "type" : "string"
          },
          "enabled" : {
            "type" : "boolean"
          },
          "auditEnabled" : {
            "type" : "boolean"
          },
          "account" : {
            "type" : "string"
          },
          "ypmId" : {
            "type" : "integer",
            "format" : "int32"
          },
          "applicationId" : {
            "type" : "string"
          },
          "certDnsDomain" : {
            "type" : "string"
          },
          "memberExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "tokenExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "serviceCertExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "roleCertExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "signAlgorithm" : {
            "type" : "string"
          },
          "serviceExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "groupExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "userAuthorityFilter" : {
            "type" : "string"
          },
          "azureSubscription" : {
            "type" : "string"
          },
          "tags" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/TagValueList"
            }
          },
          "businessService" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "modified" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "id" : {
            "$ref" : "#/components/schemas/UUID"
          }
        }
      },
      "TagValueList" : {
        "type" : "object",
        "properties" : {
          "list" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "Timestamp" : {
        "type" : "object"
      },
      "UUID" : {
        "type" : "object"
      },
      "DanglingPolicy" : {
        "type" : "object",
        "properties" : {
          "policyName" : {
            "type" : "string"
          },
          "roleName" : {
            "type" : "string"
          }
        }
      },
      "DomainDataCheck" : {
        "type" : "object",
        "properties" : {
          "danglingRoles" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "danglingPolicies" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/DanglingPolicy"
            }
          },
          "policyCount" : {
            "type" : "integer",
            "format" : "int32"
          },
          "assertionCount" : {
            "type" : "integer",
            "format" : "int32"
          },
          "roleWildCardCount" : {
            "type" : "integer",
            "format" : "int32"
          },
          "providersWithoutTrust" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "tenantsWithoutAssumeRole" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "DomainList" : {
        "type" : "object",
        "properties" : {
          "names" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "next" : {
            "type" : "string"
          }
        }
      },
      "DomainMetaStoreValidValuesList" : {
        "type" : "object",
        "properties" : {
          "validValues" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "DomainRoleMember" : {
        "type" : "object",
        "properties" : {
          "memberName" : {
            "type" : "string"
          },
          "memberRoles" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/MemberRole"
            }
          }
        }
      },
      "DomainRoleMembers" : {
        "type" : "object",
        "properties" : {
          "domainName" : {
            "type" : "string"
          },
          "members" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/DomainRoleMember"
            }
          }
        }
      },
      "MemberRole" : {
        "type" : "object",
        "properties" : {
          "roleName" : {
            "type" : "string"
          },
          "domainName" : {
            "type" : "string"
          },
          "memberName" : {
            "type" : "string"
          },
          "expiration" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "reviewReminder" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "active" : {
            "type" : "boolean"
          },
          "auditRef" : {
            "type" : "string"
          },
          "requestPrincipal" : {
            "type" : "string"
          },
          "requestTime" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "systemDisabled" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "DomainTemplateDetailsList" : {
        "type" : "object",
        "properties" : {
          "metaData" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/TemplateMetaData"
            }
          }
        }
      },
      "TemplateMetaData" : {
        "type" : "object",
        "properties" : {
          "templateName" : {
            "type" : "string"
          },
          "description" : {
            "type" : "string"
          },
          "currentVersion" : {
            "type" : "integer",
            "format" : "int32"
          },
          "latestVersion" : {
            "type" : "integer",
            "format" : "int32"
          },
          "keywordsToReplace" : {
            "type" : "string"
          },
          "timestamp" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "autoUpdate" : {
            "type" : "boolean"
          }
        }
      },
      "DomainTemplateList" : {
        "type" : "object",
        "properties" : {
          "templateNames" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "Entity" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "value" : {
            "type" : "object",
            "properties" : {
              "empty" : {
                "type" : "boolean"
              }
            },
            "additionalProperties" : {
              "type" : "object"
            }
          }
        }
      },
      "Struct" : {
        "type" : "object",
        "properties" : {
          "empty" : {
            "type" : "boolean"
          }
        },
        "additionalProperties" : {
          "type" : "object"
        }
      },
      "EntityList" : {
        "type" : "object",
        "properties" : {
          "names" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "Group" : {
        "type" : "object",
        "properties" : {
          "selfServe" : {
            "type" : "boolean"
          },
          "reviewEnabled" : {
            "type" : "boolean"
          },
          "notifyRoles" : {
            "type" : "string"
          },
          "userAuthorityFilter" : {
            "type" : "string"
          },
          "userAuthorityExpiration" : {
            "type" : "string"
          },
          "memberExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "serviceExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "tags" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/TagValueList"
            }
          },
          "name" : {
            "type" : "string"
          },
          "modified" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "groupMembers" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/GroupMember"
            }
          },
          "auditLog" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/GroupAuditLog"
            }
          },
          "auditEnabled" : {
            "type" : "boolean"
          },
          "lastReviewedDate" : {
            "$ref" : "#/components/schemas/Timestamp"
          }
        }
      },
      "GroupAuditLog" : {
        "type" : "object",
        "properties" : {
          "member" : {
            "type" : "string"
          },
          "admin" : {
            "type" : "string"
          },
          "created" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "action" : {
            "type" : "string"
          },
          "auditRef" : {
            "type" : "string"
          }
        }
      },
      "GroupMember" : {
        "type" : "object",
        "properties" : {
          "memberName" : {
            "type" : "string"
          },
          "groupName" : {
            "type" : "string"
          },
          "domainName" : {
            "type" : "string"
          },
          "expiration" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "active" : {
            "type" : "boolean"
          },
          "approved" : {
            "type" : "boolean"
          },
          "auditRef" : {
            "type" : "string"
          },
          "requestTime" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "lastNotifiedTime" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "requestPrincipal" : {
            "type" : "string"
          },
          "reviewLastNotifiedTime" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "systemDisabled" : {
            "type" : "integer",
            "format" : "int32"
          },
          "principalType" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "GroupMembership" : {
        "type" : "object",
        "properties" : {
          "memberName" : {
            "type" : "string"
          },
          "isMember" : {
            "type" : "boolean"
          },
          "groupName" : {
            "type" : "string"
          },
          "expiration" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "active" : {
            "type" : "boolean"
          },
          "approved" : {
            "type" : "boolean"
          },
          "auditRef" : {
            "type" : "string"
          },
          "requestPrincipal" : {
            "type" : "string"
          },
          "systemDisabled" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "Groups" : {
        "type" : "object",
        "properties" : {
          "list" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/Group"
            }
          }
        }
      },
      "Membership" : {
        "type" : "object",
        "properties" : {
          "memberName" : {
            "type" : "string"
          },
          "isMember" : {
            "type" : "boolean"
          },
          "roleName" : {
            "type" : "string"
          },
          "expiration" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "reviewReminder" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "active" : {
            "type" : "boolean"
          },
          "approved" : {
            "type" : "boolean"
          },
          "auditRef" : {
            "type" : "string"
          },
          "requestPrincipal" : {
            "type" : "string"
          },
          "systemDisabled" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "DomainGroupMember" : {
        "type" : "object",
        "properties" : {
          "memberName" : {
            "type" : "string"
          },
          "memberGroups" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/GroupMember"
            }
          }
        }
      },
      "DomainGroupMembers" : {
        "type" : "object",
        "properties" : {
          "domainName" : {
            "type" : "string"
          },
          "members" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/DomainGroupMember"
            }
          }
        }
      },
      "DomainGroupMembership" : {
        "type" : "object",
        "properties" : {
          "domainGroupMembersList" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/DomainGroupMembers"
            }
          }
        }
      },
      "DomainRoleMembership" : {
        "type" : "object",
        "properties" : {
          "domainRoleMembersList" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/DomainRoleMembers"
            }
          }
        }
      },
      "Policies" : {
        "type" : "object",
        "properties" : {
          "list" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/Policy"
            }
          }
        }
      },
      "Policy" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "modified" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "assertions" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/Assertion"
            }
          },
          "caseSensitive" : {
            "type" : "boolean"
          },
          "version" : {
            "type" : "string"
          },
          "active" : {
            "type" : "boolean"
          }
        }
      },
      "PolicyList" : {
        "type" : "object",
        "properties" : {
          "names" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "next" : {
            "type" : "string"
          }
        }
      },
      "ProviderResourceGroupRoles" : {
        "type" : "object",
        "properties" : {
          "domain" : {
            "type" : "string"
          },
          "service" : {
            "type" : "string"
          },
          "tenant" : {
            "type" : "string"
          },
          "roles" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/TenantRoleAction"
            }
          },
          "resourceGroup" : {
            "type" : "string"
          },
          "createAdminRole" : {
            "type" : "boolean"
          }
        }
      },
      "TenantRoleAction" : {
        "type" : "object",
        "properties" : {
          "role" : {
            "type" : "string"
          },
          "action" : {
            "type" : "string"
          }
        }
      },
      "PublicKeyEntry" : {
        "type" : "object",
        "properties" : {
          "key" : {
            "type" : "string"
          },
          "id" : {
            "type" : "string"
          }
        }
      },
      "Quota" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "subdomain" : {
            "type" : "integer",
            "format" : "int32"
          },
          "role" : {
            "type" : "integer",
            "format" : "int32"
          },
          "roleMember" : {
            "type" : "integer",
            "format" : "int32"
          },
          "policy" : {
            "type" : "integer",
            "format" : "int32"
          },
          "assertion" : {
            "type" : "integer",
            "format" : "int32"
          },
          "entity" : {
            "type" : "integer",
            "format" : "int32"
          },
          "service" : {
            "type" : "integer",
            "format" : "int32"
          },
          "serviceHost" : {
            "type" : "integer",
            "format" : "int32"
          },
          "publicKey" : {
            "type" : "integer",
            "format" : "int32"
          },
          "group" : {
            "type" : "integer",
            "format" : "int32"
          },
          "groupMember" : {
            "type" : "integer",
            "format" : "int32"
          },
          "modified" : {
            "$ref" : "#/components/schemas/Timestamp"
          }
        }
      },
      "AliasTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          }
        }
      },
      "ArrayTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "items" : {
            "type" : "string"
          },
          "size" : {
            "type" : "integer",
            "format" : "int32"
          },
          "minSize" : {
            "type" : "integer",
            "format" : "int32"
          },
          "maxSize" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "BytesTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "size" : {
            "type" : "integer",
            "format" : "int32"
          },
          "minSize" : {
            "type" : "integer",
            "format" : "int32"
          },
          "maxSize" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "EnumElementDef" : {
        "type" : "object",
        "properties" : {
          "symbol" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          }
        }
      },
      "EnumTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "elements" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/EnumElementDef"
            }
          }
        }
      },
      "ExceptionDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          }
        }
      },
      "MapTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "keys" : {
            "type" : "string"
          },
          "items" : {
            "type" : "string"
          },
          "size" : {
            "type" : "integer",
            "format" : "int32"
          },
          "minSize" : {
            "type" : "integer",
            "format" : "int32"
          },
          "maxSize" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "Number" : {
        "type" : "object",
        "properties" : {
          "Int8" : {
            "type" : "string",
            "format" : "byte"
          },
          "Int16" : {
            "type" : "integer",
            "format" : "int32"
          },
          "Int32" : {
            "type" : "integer",
            "format" : "int32"
          },
          "Int64" : {
            "type" : "integer",
            "format" : "int64"
          },
          "Float32" : {
            "type" : "number",
            "format" : "float"
          },
          "Float64" : {
            "type" : "number",
            "format" : "double"
          }
        }
      },
      "NumberTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "min" : {
            "$ref" : "#/components/schemas/Number"
          },
          "max" : {
            "$ref" : "#/components/schemas/Number"
          }
        }
      },
      "Resource" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "method" : {
            "type" : "string"
          },
          "path" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "inputs" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/ResourceInput"
            }
          },
          "outputs" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/ResourceOutput"
            }
          },
          "auth" : {
            "$ref" : "#/components/schemas/ResourceAuth"
          },
          "expected" : {
            "type" : "string"
          },
          "alternatives" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "exceptions" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/ExceptionDef"
            }
          },
          "async" : {
            "type" : "boolean"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "consumes" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "produces" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "name" : {
            "type" : "string"
          }
        }
      },
      "ResourceAuth" : {
        "type" : "object",
        "properties" : {
          "authenticate" : {
            "type" : "boolean"
          },
          "action" : {
            "type" : "string"
          },
          "resource" : {
            "type" : "string"
          },
          "domain" : {
            "type" : "string"
          }
        }
      },
      "ResourceInput" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "type" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "pathParam" : {
            "type" : "boolean"
          },
          "queryParam" : {
            "type" : "string"
          },
          "header" : {
            "type" : "string"
          },
          "pattern" : {
            "type" : "string"
          },
          "optional" : {
            "type" : "boolean"
          },
          "flag" : {
            "type" : "boolean"
          },
          "context" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "default" : {
            "type" : "object"
          }
        }
      },
      "ResourceOutput" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "type" : {
            "type" : "string"
          },
          "header" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "optional" : {
            "type" : "boolean"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          }
        }
      },
      "Schema" : {
        "type" : "object",
        "properties" : {
          "namespace" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "version" : {
            "type" : "integer",
            "format" : "int32"
          },
          "comment" : {
            "type" : "string"
          },
          "types" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/Type"
            }
          },
          "resources" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/Resource"
            }
          },
          "base" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          }
        }
      },
      "StringTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "pattern" : {
            "type" : "string"
          },
          "values" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "minSize" : {
            "type" : "integer",
            "format" : "int32"
          },
          "maxSize" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "StructFieldDef" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "type" : {
            "type" : "string"
          },
          "optional" : {
            "type" : "boolean"
          },
          "comment" : {
            "type" : "string"
          },
          "items" : {
            "type" : "string"
          },
          "keys" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "default" : {
            "type" : "object"
          }
        }
      },
      "StructTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "fields" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/StructFieldDef"
            }
          },
          "closed" : {
            "type" : "boolean"
          }
        }
      },
      "Type" : {
        "type" : "object",
        "properties" : {
          "BaseType" : {
            "type" : "string",
            "enum" : [ "Bool", "Int8", "Int16", "Int32", "Int64", "Float32", "Float64", "Bytes", "String", "Timestamp", "Symbol", "UUID", "Array", "Map", "Struct", "Enum", "Union", "Any" ]
          },
          "StructTypeDef" : {
            "$ref" : "#/components/schemas/StructTypeDef"
          },
          "MapTypeDef" : {
            "$ref" : "#/components/schemas/MapTypeDef"
          },
          "ArrayTypeDef" : {
            "$ref" : "#/components/schemas/ArrayTypeDef"
          },
          "EnumTypeDef" : {
            "$ref" : "#/components/schemas/EnumTypeDef"
          },
          "UnionTypeDef" : {
            "$ref" : "#/components/schemas/UnionTypeDef"
          },
          "StringTypeDef" : {
            "$ref" : "#/components/schemas/StringTypeDef"
          },
          "BytesTypeDef" : {
            "$ref" : "#/components/schemas/BytesTypeDef"
          },
          "NumberTypeDef" : {
            "$ref" : "#/components/schemas/NumberTypeDef"
          },
          "AliasTypeDef" : {
            "$ref" : "#/components/schemas/AliasTypeDef"
          }
        }
      },
      "UnionTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "variants" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "ResourceAccess" : {
        "type" : "object",
        "properties" : {
          "principal" : {
            "type" : "string"
          },
          "assertions" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/Assertion"
            }
          }
        }
      },
      "ResourceAccessList" : {
        "type" : "object",
        "properties" : {
          "resources" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/ResourceAccess"
            }
          }
        }
      },
      "Role" : {
        "type" : "object",
        "properties" : {
          "selfServe" : {
            "type" : "boolean"
          },
          "memberExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "tokenExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "certExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "signAlgorithm" : {
            "type" : "string"
          },
          "serviceExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "memberReviewDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "serviceReviewDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "reviewEnabled" : {
            "type" : "boolean"
          },
          "notifyRoles" : {
            "type" : "string"
          },
          "userAuthorityFilter" : {
            "type" : "string"
          },
          "userAuthorityExpiration" : {
            "type" : "string"
          },
          "groupExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "groupReviewDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "tags" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/TagValueList"
            }
          },
          "name" : {
            "type" : "string"
          },
          "modified" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "members" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "roleMembers" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/RoleMember"
            }
          },
          "trust" : {
            "type" : "string"
          },
          "auditLog" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/RoleAuditLog"
            }
          },
          "auditEnabled" : {
            "type" : "boolean"
          },
          "lastReviewedDate" : {
            "$ref" : "#/components/schemas/Timestamp"
          }
        }
      },
      "RoleAuditLog" : {
        "type" : "object",
        "properties" : {
          "member" : {
            "type" : "string"
          },
          "admin" : {
            "type" : "string"
          },
          "created" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "action" : {
            "type" : "string"
          },
          "auditRef" : {
            "type" : "string"
          }
        }
      },
      "RoleMember" : {
        "type" : "object",
        "properties" : {
          "memberName" : {
            "type" : "string"
          },
          "expiration" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "reviewReminder" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "active" : {
            "type" : "boolean"
          },
          "approved" : {
            "type" : "boolean"
          },
          "auditRef" : {
            "type" : "string"
          },
          "requestTime" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "lastNotifiedTime" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "requestPrincipal" : {
            "type" : "string"
          },
          "reviewLastNotifiedTime" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "systemDisabled" : {
            "type" : "integer",
            "format" : "int32"
          },
          "principalType" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "RoleList" : {
        "type" : "object",
        "properties" : {
          "names" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "next" : {
            "type" : "string"
          }
        }
      },
      "Roles" : {
        "type" : "object",
        "properties" : {
          "list" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/Role"
            }
          }
        }
      },
      "ServerTemplateList" : {
        "type" : "object",
        "properties" : {
          "templateNames" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "ServiceIdentities" : {
        "type" : "object",
        "properties" : {
          "list" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/ServiceIdentity"
            }
          }
        }
      },
      "ServiceIdentity" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "description" : {
            "type" : "string"
          },
          "publicKeys" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/PublicKeyEntry"
            }
          },
          "providerEndpoint" : {
            "type" : "string"
          },
          "modified" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "executable" : {
            "type" : "string"
          },
          "hosts" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "user" : {
            "type" : "string"
          },
          "group" : {
            "type" : "string"
          }
        }
      },
      "ServiceIdentityList" : {
        "type" : "object",
        "properties" : {
          "names" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "next" : {
            "type" : "string"
          }
        }
      },
      "ServicePrincipal" : {
        "type" : "object",
        "properties" : {
          "domain" : {
            "type" : "string"
          },
          "service" : {
            "type" : "string"
          },
          "token" : {
            "type" : "string"
          }
        }
      },
      "Status" : {
        "type" : "object",
        "properties" : {
          "code" : {
            "type" : "integer",
            "format" : "int32"
          },
          "message" : {
            "type" : "string"
          }
        }
      },
      "Template" : {
        "type" : "object",
        "properties" : {
          "roles" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/Role"
            }
          },
          "policies" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/Policy"
            }
          },
          "services" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/ServiceIdentity"
            }
          },
          "metadata" : {
            "$ref" : "#/components/schemas/TemplateMetaData"
          }
        }
      },
      "TenantResourceGroupRoles" : {
        "type" : "object",
        "properties" : {
          "domain" : {
            "type" : "string"
          },
          "service" : {
            "type" : "string"
          },
          "tenant" : {
            "type" : "string"
          },
          "roles" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/TenantRoleAction"
            }
          },
          "resourceGroup" : {
            "type" : "string"
          }
        }
      },
      "UserAuthorityAttributeMap" : {
        "type" : "object",
        "properties" : {
          "attributes" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/UserAuthorityAttributes"
            }
          }
        }
      },
      "UserAuthorityAttributes" : {
        "type" : "object",
        "properties" : {
          "values" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "UserList" : {
        "type" : "object",
        "properties" : {
          "names" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "UserToken" : {
        "type" : "object",
        "properties" : {
          "token" : {
            "type" : "string"
          },
          "header" : {
            "type" : "string"
          }
        }
      },
      "SubDomain" : {
        "type" : "object",
        "properties" : {
          "description" : {
            "type" : "string"
          },
          "org" : {
            "type" : "string"
          },
          "enabled" : {
            "type" : "boolean"
          },
          "auditEnabled" : {
            "type" : "boolean"
          },
          "account" : {
            "type" : "string"
          },
          "ypmId" : {
            "type" : "integer",
            "format" : "int32"
          },
          "applicationId" : {
            "type" : "string"
          },
          "certDnsDomain" : {
            "type" : "string"
          },
          "memberExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "tokenExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "serviceCertExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "roleCertExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "signAlgorithm" : {
            "type" : "string"
          },
          "serviceExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "groupExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "userAuthorityFilter" : {
            "type" : "string"
          },
          "azureSubscription" : {
            "type" : "string"
          },
          "tags" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/TagValueList"
            }
          },
          "businessService" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "adminUsers" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "templates" : {
            "$ref" : "#/components/schemas/DomainTemplateList"
          },
          "parent" : {
            "type" : "string"
          }
        }
      },
      "TopLevelDomain" : {
        "type" : "object",
        "properties" : {
          "description" : {
            "type" : "string"
          },
          "org" : {
            "type" : "string"
          },
          "enabled" : {
            "type" : "boolean"
          },
          "auditEnabled" : {
            "type" : "boolean"
          },
          "account" : {
            "type" : "string"
          },
          "ypmId" : {
            "type" : "integer",
            "format" : "int32"
          },
          "applicationId" : {
            "type" : "string"
          },
          "certDnsDomain" : {
            "type" : "string"
          },
          "memberExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "tokenExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "serviceCertExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "roleCertExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "signAlgorithm" : {
            "type" : "string"
          },
          "serviceExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "groupExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "userAuthorityFilter" : {
            "type" : "string"
          },
          "azureSubscription" : {
            "type" : "string"
          },
          "tags" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/TagValueList"
            }
          },
          "businessService" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "adminUsers" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "templates" : {
            "$ref" : "#/components/schemas/DomainTemplateList"
          }
        }
      },
      "UserDomain" : {
        "type" : "object",
        "properties" : {
          "description" : {
            "type" : "string"
          },
          "org" : {
            "type" : "string"
          },
          "enabled" : {
            "type" : "boolean"
          },
          "auditEnabled" : {
            "type" : "boolean"
          },
          "account" : {
            "type" : "string"
          },
          "ypmId" : {
            "type" : "integer",
            "format" : "int32"
          },
          "applicationId" : {
            "type" : "string"
          },
          "certDnsDomain" : {
            "type" : "string"
          },
          "memberExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "tokenExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "serviceCertExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "roleCertExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "signAlgorithm" : {
            "type" : "string"
          },
          "serviceExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "groupExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "userAuthorityFilter" : {
            "type" : "string"
          },
          "azureSubscription" : {
            "type" : "string"
          },
          "tags" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/TagValueList"
            }
          },
          "businessService" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "templates" : {
            "$ref" : "#/components/schemas/DomainTemplateList"
          }
        }
      },
      "DefaultAdmins" : {
        "type" : "object",
        "properties" : {
          "admins" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "DomainMeta" : {
        "type" : "object",
        "properties" : {
          "description" : {
            "type" : "string"
          },
          "org" : {
            "type" : "string"
          },
          "enabled" : {
            "type" : "boolean"
          },
          "auditEnabled" : {
            "type" : "boolean"
          },
          "account" : {
            "type" : "string"
          },
          "ypmId" : {
            "type" : "integer",
            "format" : "int32"
          },
          "applicationId" : {
            "type" : "string"
          },
          "certDnsDomain" : {
            "type" : "string"
          },
          "memberExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "tokenExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "serviceCertExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "roleCertExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "signAlgorithm" : {
            "type" : "string"
          },
          "serviceExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "groupExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "userAuthorityFilter" : {
            "type" : "string"
          },
          "azureSubscription" : {
            "type" : "string"
          },
          "tags" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/TagValueList"
            }
          },
          "businessService" : {
            "type" : "string"
          }
        }
      },
      "DomainTemplate" : {
        "type" : "object",
        "properties" : {
          "templateNames" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "params" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/TemplateParam"
            }
          }
        }
      },
      "TemplateParam" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "value" : {
            "type" : "string"
          }
        }
      },
      "GroupMeta" : {
        "type" : "object",
        "properties" : {
          "selfServe" : {
            "type" : "boolean"
          },
          "reviewEnabled" : {
            "type" : "boolean"
          },
          "notifyRoles" : {
            "type" : "string"
          },
          "userAuthorityFilter" : {
            "type" : "string"
          },
          "userAuthorityExpiration" : {
            "type" : "string"
          },
          "memberExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "serviceExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "tags" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/TagValueList"
            }
          }
        }
      },
      "GroupSystemMeta" : {
        "type" : "object",
        "properties" : {
          "auditEnabled" : {
            "type" : "boolean"
          }
        }
      },
      "PolicyOptions" : {
        "type" : "object",
        "properties" : {
          "version" : {
            "type" : "string"
          },
          "fromVersion" : {
            "type" : "string"
          }
        }
      },
      "RoleMeta" : {
        "type" : "object",
        "properties" : {
          "selfServe" : {
            "type" : "boolean"
          },
          "memberExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "tokenExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "certExpiryMins" : {
            "type" : "integer",
            "format" : "int32"
          },
          "signAlgorithm" : {
            "type" : "string"
          },
          "serviceExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "memberReviewDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "serviceReviewDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "reviewEnabled" : {
            "type" : "boolean"
          },
          "notifyRoles" : {
            "type" : "string"
          },
          "userAuthorityFilter" : {
            "type" : "string"
          },
          "userAuthorityExpiration" : {
            "type" : "string"
          },
          "groupExpiryDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "groupReviewDays" : {
            "type" : "integer",
            "format" : "int32"
          },
          "tags" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/TagValueList"
            }
          }
        }
      },
      "RoleSystemMeta" : {
        "type" : "object",
        "properties" : {
          "auditEnabled" : {
            "type" : "boolean"
          }
        }
      },
      "ServiceIdentitySystemMeta" : {
        "type" : "object",
        "properties" : {
          "providerEndpoint" : {
            "type" : "string"
          }
        }
      },
      "Tenancy" : {
        "type" : "object",
        "properties" : {
          "domain" : {
            "type" : "string"
          },
          "service" : {
            "type" : "string"
          },
          "resourceGroups" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "createAdminRole" : {
            "type" : "boolean"
          }
        }
      }
    }
  }
}