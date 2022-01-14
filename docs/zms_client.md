# ZMS Client Utility
---------------------

* [Overview](#overview)
* [Getting Software](#getting-software)
* [Prerequisites](#prerequisites)
* [Getting Help](#getting-help)
* [Specifying ZMS Environments](#specifying-zms-environments)
* [How the ZMS Client Authenticates](#how-the-zms-client-authenticates)
* [Listing registered domains in Athenz](#listing-registered-domains-in-athenz)
* [Displaying Administrators for a Product Domain](#displaying-administrators-for-a-product-domain)
* [Adding Domains](#adding-domains)
    * [Parameters](#parameters)
    * [Examples](#examples)
* [Registering Personal Domains](#registering-personal-domains)
* [Adding and Removing Administrators](#adding-and-removing-administrators)
* [Adding a Group Role](#adding-a-group-role)
    * [Parameters](#parameters-1)
    * [Example](#example)
* [Managing a Group Role Membership](#managing-a-group-role-membership)
    * [Parameters](#parameters-2)
    * [Example](#example-1)
* [Adding a temporary Role Membership with expiration date](#adding-a-temporary-role-membership-with-expiration-date)   
     * [Parameters](#parameters-3)
     * [Example](#example-2)
* [Adding a Policy](#adding-a-policy)
    * [Parameters](#parameters-4)
    * [Example](#example-3)

## Overview
----------

The ZMS client utility allows administrators to manage Athenz domains,
to check domain details, create personal domains, and add other
administrators.

## Getting Software
-------------------

Download latest ZMS Client utility binary release from
[Maven Central](https://search.maven.org/artifact/com.yahoo.athenz/athenz-utils):
click on the `Browse` button, choose the latest version directory and then
download the `athenz-utils-<latest-version>-bin.tar.gz`.
  
```shell
$ tar xvfz athenz-utils-X.Y-bin.tar.gz
```

## Prerequisites
----------------

Before you can use the ZMS client utility, you need to have
asked the Athenz administrators to create your top level domain.

## Getting Help
---------------

The help argument for the utility will display all commands available
through utility.

    $ zms-cli help

To get additional details about a specific command:

    $ zms-cli help [command]

For example, to get complete details on how to add a domain including
examples:

    $ zms-cli help add-domain

## Specifying ZMS Environments
------------------------------

Use the `-z` option to point to the required environment for executing commands.

    $ zms-cli -z https://zms-server.athenzcompany.com:4443/zms/v1 -d athenz show-domain


## How the ZMS Client Authenticates
-----------------------------------

The Athenz ZMS server requires the user to provide its `UserToken` or use a User 
certificate and private key for MTLS to authenticate with ZMS 
(depending on the Principal Authority used).

ZMS will then authorize the request based on the configured authority.

## Listing registered domains in Athenz
---------------------------------------

To find out what domains have been provisioned in Athenz, run the
following:

    $ zms-cli list-domain

The list-domain command also takes an optional prefix argument to filter
the domains and only return those that start with the specified string.
For example, if the user wants to list only the domains that have been
configured in the `athenz` product domain, he/she will run the following
command:

    $ zms-cli list-domain athenz
        domains:
      - athenz
      - athenz.ci
      - athenz.qa

## Displaying Administrators for a Product Domain
-------------------------------------------------

To view the full list of administrators for a given domain, run the
following:

    $ zms-cli -d <domain-name> show-role admin

For example, to view the Athenz system administrators for the domain
`media.news`:

    $ zms-cli -d media.news show-role admin

## Adding Domains
-----------------

The Top Level Product Domains in ZMS are provisioned by Athenz
administrators.

Once the Product Domain has been created, the designated domain
administrators can create any subdomains as necessary.

To create a new domain, the administrator uses the `add-domain` command:

    $ zms-cli add-domain <product sub domain> [<admin1> <admin2> ...]

### Parameters

    <domain>

The name of the domain to be added, which could either be a product
domain or a subdomain. For example, to add a subdomain called `storage`
in the `athenz` domain, the value for `<domain>` would be
`athenz.storage`. The parent domain must exist before a subdomain
can be created. The domain name can only include any letters, digits and
the '-' character. The maximum length of the domain name (including all
subdomain parts) is 256 bytes.

    [<admin1> ...]

A space-separated list of administrators for the domain. The user
creating the domain is automatically added as an administrator.

### Examples

If user `joe` executes the command below, the product domain `coretech`
is created and will include `user.joe` as an administrator:

    $ zms-cli add-domain coretech

When user `joe` executes the command below, the sub domain `athenz.ci`
is created and will have the administrators `yby.joe`, `yby.john`, and
`yby.jane`:

    $ zms-cli add-domain athenz.ci yby.john yby.jane

## Registering Personal Domains
-------------------------------

ZMS supports Personal Domains. These domains are provisioned for users
in the User `user` domain and have the same functionality as Product
Domains in Athenz. The Personal Domain uses the syntax `user.<user-id>`
and can have configured number of subdomains (default 2).

For example, if your user ID is joe and you'd like to create a
Personal Domain, you would run the following command:

    $ zms-cli add-domain user.joe

Then, to create a subdomain called `athenz-test` in your Personal
Domain, you would run the following command:

    $ zms-cli add-domain user.joe.athenz-test

If the user wants to list only his/her personal domains that have been
registered, he/she will run the following command:

    $ zms-cli list-domain user.<user-id>

## Adding and Removing Administrators
-------------------------------------

Domain administrators are the principals listed as members of the role
`admin`. When you create a domain, the role and corresponding policy
`role` are created. Administrators can manage the list of current domain
administrators by adding or removing members in the `admin` role.

To add one or more administrators:

    $ zms-cli -d <domain> add-member admin <user1> [<user2> ...]

To remove existing domain administrators:

    $ zms-cli -d <domain> delete-member admin <user1> [<user2> ...]

ZMS allows you to remove yourself from the `admin` role.

    Once you've been removed, you'll need to ask another domain
    administrator to re-add you to the `admin` role.

## Adding a Regular Role
------------------------

To add new regular role to a domain, the administrator will execute the
following zms-cli command:

    $ zms-cli -d <domain> add-regular-role <role> <member> [<member> ...]

<h3 id="parameters-1">Parameters</h3>

    <domain>

The name of the domain that the new role belongs to.

    <role>

The name of the new role to be added.

    <member> [<member> ...]

A space-separated list of members for the role. At least one member must
be specified. If the member is a regular user, then user's id
must be prefixed with `user.`. Once the group has been created, the
administrator can add and/or delete members using the `add-member` and
`delete-member` commands.

### Example

When the domain administrator executes the command below, a new role
called `readers` will be added to the the domain `athenz.ci` will
have the following members: user - `user.john` and service -
`media.sports.storage`:

    $ zms-cli -d athenz.ci add-regular-role readers user.john media.sports.storage

## Managing a Group Role Membership
-----------------------------------

To add and/or delete members to/from a given role in a domain, the
administrator will execute the following zms-cli commands:

    $ zms-cli -d <domain> add-member <role> <member> [<member> ...]
    $ zms-cli -d <domain> delete-member <role> <member> [<member> ...]

<h3 id="parameters-2">Parameters</h3>

    <domain>

The name of the domain that the role belongs to.

    <role>

The name of the role that will be modified to add or remove members.

    <member> [<member> ...]

A space-separated list of members to be added to the role or to be
removed from the role. At least one member must be specified. If the
member is a regular user, the user's id must be prefixed with
`user.`.

When specifying service identities as members you must provide
the full service name in then &lt;domain-name&gt;.&lt;service-name&gt; format.

<h3 id="example-1">Example</h3>

To add two new members: service "media.sports.storage" and user
"yby.john", to a role called "readers" in the domain "athenz", the
domain administrator will execute the following command:

    $ zms-cli -d athenz add-member readers yby.john media.sports.storage

To delete member "media.sports.storage" from a role called "writers" in
the domain "athenz", the domain administrator will execute the
following command:

    $ zms-cli -d athenz delete-member writers media.sports.storage

## Adding a temporary Role Membership with expiration date
----------------------------------------------------------

To add a temporary member to a given role in a domain, the administrator
will execute the following zms-cli commands:

```
$ zms-cli -d <domain> add-temporary-member <role> <member> <expiration>
```

<h3 id="parameters-3">Parameters</h3>

```
<domain>
```

The name of the domain that the role belongs to.

```
<role>
```

The name of the role that will be modified to add.

```
<member>
```

A member to be added to the role. Only one member must be specified. If
the member is a regular user, the user's short id must be prefixed
with `user.`.

```
<expiration>
```

Expiration date. It is expected to be in UTC timezone in the form of
`YYYY-MM-DDTHH:MM:SSZ` - for example: 2017-03-02T15:04:00Z

<h3 id="example-2">Example</h3>

To add a new member: user `user.john`, to a role called `readers` in the
domain `sports.nhl`, with expiration date set to 1PM UTC time on Sep. 3rd, 2018,
the domain administrator will execute the following command:

```
$ zms-cli -d sports.nhl add-temporary-member readers user.john 2018-09-03T13:00:00Z
```

## Adding a Policy
------------------

To add new policy to a domain, the administrator will execute the
following zms-cli command:

    $ zms-cli -d <domain> add-policy <policy> [<assertion>]

<h3 id="parameters-4">Parameters</h3>

    <domain>

The name of the domain that the new policy belongs to.

    <policy>

The name of the new policy to be added.

    [<assertion>] where <assertion> is '<effect> <action> to <role> on <resource>'

The value effect must be either 'grant' or 'deny'. The action is the
domain administrator defined action available for the resource (e.g.
read, write, delete). The role is the name of the role this assertion
applies to. The resource is the name of the resource this assertion
applies to. Once the policy has been created, the administrator can add
and/or delete assertions using the `add-assertion` and
`delete-assertion` commands.

<h3 id="example-3">Example</h3>

When the domain administrator executes the command below, a new policy
called `writers` will be added to the the domain `athenz.ci` that
will grant `write` access to all the members of the `sports_writers`
role on `articles.sports.*`:

    $ zms-cli -d athenz.ci add-policy writers grant write to sports_writers on 'articles.sports.*'
