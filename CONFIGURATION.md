Configuration of the ldap library
================================

General configuration
---------------------

All configuration parameters should be given to the constructor of the `Jelix\Ldap\Ldap` object.

Example of a such array:

```php
$config = array(
    'hostname' => 'localhost',
    'port' => '389',
    'tlsMode' => 'starttls', // empty, "starttls" or "ldaps" (ldaps by default if port 636)
    'adminUserDn' => "cn=admin,ou=admins,dc=acme"
    'adminPassword' => "Sup3rP4ssw0rd",
    'searchUserBaseDN' => "dc=XY,dc=fr",
    'searchUserFilter' => "(&(objectClass=posixAccount)(uid=%%LOGIN%%))",
    'searchAttributes' => "uid:login,givenName:firstname,sn:lastname,mail:email",
    'searchGroupFilter' => "(&(objectClass=posixGroup)(cn=XYZ*)(memberUid=%%LOGIN%%))",
    'searchGroupProperty' => "cn",
    'searchGroupBaseDN' => '',
);

$ldap = new Jelix\Ldap\Ldap($config);

```

Parameters are described into sections below.

Connection configuration
------------------------

Parameters for the connection configuration are:

- `hostname`: the name of the ldap server.
- `port`: the port of the ldap server.
- `tlsMode`: the security mode for the connection.

With `tlsMode`, you should indicate if you are using the ldap protocol 
without encryption (`'tlsMode' => ''` or `'tlsMode' => 'none'`), the ldap protocol with STARTTLS, 
(`'tlsMode' => 'starttls'`) or if you are using the ldaps protocol (`'tlsMode' => 'ldaps'`).
Any other value is refused. The value is case-insensitive.

**Warning**: without encryption, passwords of the admin user and of users are sent in clear
text over the network. Use it only on a trusted network (or a local connection).

When TLS is used, the certificate of the server is always verified, whatever the
`TLS_REQCERT` value into `ldap.conf` or the `LDAPTLS_REQCERT` environment variable.
TLS 1.2 is the minimum version of the protocol.

If you use the standard port 389, you have the choice between no encryption (empty value)
or `starttls`, for the `tlsMode` setting.

If you are using the port 636, it automatically uses the ldaps protocol. In this
case, setting `tlsMode` to `ldaps` is optional.

Since ldaps is deprecated in OpenLdap, the best solution is to use the port 389
with `'tlsMode' => 'starttls'`.


Other connection parameters:

- `networkTimeout`: timeout in seconds to connect to the server (10 by default).
- `timeLimit`: time limit in seconds for search operations (10 by default).

Using client certificates and custom CA certificates
----------------------------------------------------

If the server is using a custom or self-signed CA certificate, indicate the path to this certificate
into the configuration parameter `clientTLSCACertificateFile`.

If the server requires a client certificate, indicate the path to the client certificate
into the configuration parameter `clientTLSCertificateFile` and the path to the client key
into the configuration parameter `clientTLSKeyFile`.

**Warning**: don't use these parameters on a PHP server which serves different PHP applications, because these
openldap settings are global to the PHP process and can affect other PHP applications running on the same server. For the same reason, you cannot use several instances of the Ldap class with different client certificates, during the same http request. All connections will use the same client certificate. This is not a limitation of our Ldap library, but of PHP and OpenLdap.

If you are using PHP-FPM, you can configure a pool dedicated to your application, so processes are not shared
with other applications.

An other solution is to use the Ldap class in a separate process by using the php function `proc_open()` and
other proc functions.


Configuration properties for the admin user
-------------------------------------------

The library needs to query the directory with a user having some rights allowing 
to search a user, to get his attributes, his groups, change a password etc...
He's called the "admin" in the library.

You must indicate in `adminUserDn` and `adminPassword`, the DN (Distinguished Name) 
and the password of this user. 

Configuration properties for user data
--------------------------------------

Some methods like `getUser` or `verifyAuthentication` loads some ldap attributes
corresponding to the user, and return an object `Jelix\Ldap\UserLdapAttributes`.
This object contains some ldap attributes, but also some user attributes.

You should indicate which ldap attributes should be retrieved, and which
user attributes will receive the ldap attributes values.

You indicate such information into the `searchAttributes` property. It is a 
list of assignments. It can be a string or an array

In a string, assignments are separated by a coma. An assignment could be written like:

- `<ldap attribute>:<user attribute>`: the value of the given ldap attribute will be stored 
  into the given user attribute
- `<ldap attribute>`: the value of the given ldap attribute will be stored into the user 
  attribute having the same name
- `<ldap attribute>:` (notice the colon at the end): the ldap attribute is retrieved, but 
  no assignment is made. The value can be used into other pattern like the `bindUserDN` pattern.

In this example, `searchAttributes="uid:login,givenName,sn:lastname,mail:email,dn:"`:

- the value of the `uid` ldap attribute will be stored into the `login` attribute 
- the value of the `sn` ldap attribute will be stored into the `lastname` attribute
- the value of the `givenName` ldap attribute will be stored into an attribute that
  have the same name, as there is no user attribute name nor `:`.
- there will not be mapping for the `dn` property. There is a `:` without a user attribute
  name. It will be read from ldap, and could be used into the `bindUserDN` DN template.
  (see below).

If `searchAttributes` is an array, it can be filled like this:

```php
array(
    '<ldap attribute>' => '<user attribute>',
    '<ldap attribute>' => '=', // the user attribute has the same name as the ldap attribute 
    '<ldap attribute>' => '',  // the ldap attribute is retrieved but not mapped into a user attribute
)
```

Names of ldap attributes are case-insensitive. Ldap attributes are stored into
the `ldapAttributes` property of `Jelix\Ldap\UserLdapAttributes` with the name
given into `searchAttributes`. For multi-valued attributes, `ldapAttributes` contains
only the first value. All values are available into the `ldapAttributesValues` property.

Configuration properties for authentication
-------------------------------------------

Before to try to authenticate the user against the ldap, the library search and retrieves
user properties from the ldap. It uses three configuration parameters : `searchUserBaseDN`,
`searchUserFilter` and `searchAttributes`.

The `searchUserBaseDN` parameter indicates the path of the Ldap subtree to search in. 
Example: `'searchUserBaseDN' => "ou=ADAM users,o=Microsoft,c=US"`.

The `searchUserFilter` should contain the ldap query, and a `%%LOGIN%%` placeholder
that will be replaced by the login given by the user.

Example: `'searchUserFilter' => "(&(objectClass=posixAccount)(uid=%%LOGIN%%))"`

Note that you can indicate several search filters and several base DN, if you have
complex ldap structure. Use an array instead of a single string:

```php
array(
'searchUserBaseDN' => [
  "ou=ADAM users,o=Microsoft,c=US",
  "ou=FOO users,o=Microsoft,c=US"
  ],
'searchUserFilter' => [
  "(&(objectClass=posixAccount)(uid=%%LOGIN%%))",
  "(&(objectClass=posixAccount)(cn=%%LOGIN%%))",
  ]
)
```

You can have only one `searchUserBaseDN` value and several `searchUserFilter` values. The same 
base DN will be used for each filter.

You can have several `searchUserBaseDN` values and only one `searchUserFilter` value. The search will
be done for each base DN, but with the same query.

And you can have several `searchUserBaseDN` values and several `searchUserFilter` values. 
In this case each filter should correspond to each base DN. You must then have same count
of `searchUserBaseDN` values and `searchUserFilter` values.

In the previous example, a first search will be made with the filter `(&(objectClass=posixAccount)(uid=%%LOGIN%%))`
will be used with the base DN `ou=ADAM users,o=Microsoft,c=US`. And if the user is not
found, a second search will be made with the filter `(&(objectClass=posixAccount)(cn=%%LOGIN%%))` 
and the base DN `ou=FOO users,o=Microsoft,c=US`.

If there is a result, the DN of the found entry will be used to "bind" to the ldap 
server with the password given by the user. (set the `verifyAuthentication()` method).
If several entries match the filter for a same base DN, the login is considered as
ambiguous and an exception is thrown.

Instead of the DN of the entry, you can indicate into `bindAttribute` an ldap attribute
of the entry that contains the DN to use for the bind. If this attribute is missing or empty,
the authentication fails.

The login given to methods of the library is escaped before being inserted into filters, so
characters like `*` or `(` are not interpreted. Logins having control characters, are refused. Spaces at the beginning 
or at the end of the login are removed before the search.

Note that comparisons in ldap are often case-insensitive: `verifyAuthentication('JOHN', ...)`
may authenticate the user `john`. Your application should use the login returned into
the `UserLdapAttributes` object, not the login given by the user.

Retrieving groups of the user
-----------------------------

You may want to retrieve the list of ldap groups where the user is in.

You should then indicate into `searchGroupFilter` the ldap query that will
retrieve the groups of the user.

Example: `'searchGroupFilter' => "(&(objectClass=posixGroup)(member=%%USERDN%%))"`

`%%USERDN%%` is replaced by the user dn.`%%LOGIN%%` is replaced by the login.  
You can also use any ldap attributes you indicate into `searchAttributes`, 
between `%%`. Example: `'searchGroupFilter' => "(&(objectClass=posixGroup)(member=%%givenName%%))"`
All these values are escaped before being inserted into the filter.

With `searchGroupProperty`, you must indicate the ldap attribute that
contains the group name. Ex: `searchGroupProperty="cn"`.

You may also indicate the base DN for the search, into `searchGroupBaseDN`. Example:
`'searchGroupBaseDN' => "ou=Groups,dc=Acme,dc=pt"`.

If you don't want the loading of the groups list, leave `searchGroupFilter` empty.


Enable ldap modification features
---------------------------------

The main goal of this library is to authenticate a user against a ldap server. 
But you may want to use it to manage an LDAP user account: modifying his password, modifying his attributes, deleting it, or to create a new user.

These features are disabled by default. 

To enable these features, you must set `true` to some LDAP parameters:

- `featureCreateUser` : to enable the creation of a new user, and to be able to call the method `createUser()`
- `featureUpdateUser` : to enable the modification of a user attributes, and to be able to call the method `updateUser()`
- `featureDeleteUser` : to enable the deletion of a user, and to be able to call the method `deleteUser()`
- `featureChangePassword` : to enable the modification of a user password, and to be able to call the method `changePassword()`

`updateUser()` can modify only ldap attributes that are listed into `searchAttributes`.
Passwords (`userPassword`, `unicodePwd`) and `objectClass` cannot be modified with this method.

Creating users
--------------

- `newUserDN`: the DN of the new user. `%%LOGIN%%` is replaced by the login. You can also
  use `<attribute>=%?%`, which is replaced by the value of the given attribute of the new user.
  Values are escaped. Or you can indicate `$<attribute>`: the DN is the value of the
  given attribute (this value is not escaped, it should be a valid DN).
- `newUserLdapAttributes`: the ldap attributes of the new user. It can be a string
  like `"objectClass:inetOrgPerson,userPassword:%%PASSWORD%%,cn:%%REALNAME%%,sn:%%REALNAME%%"`
  (indicate several times the same attribute for a multi-valued attribute), or an array
  like `['objectClass' => ['inetOrgPerson', 'organizationalPerson'], 'cn' => '%%REALNAME%%']`.
  Use an array if a value contains a comma. `%%LOGIN%%`, `%%REALNAME%%` and `%%PASSWORD%%`
  placeholders can be used anywhere into values. By default, `objectClass`, `userPassword`,
  `cn` and `sn` are set.

Passwords
---------

With `passwordLdapHashAlgo`, you indicate how passwords are stored by `createUser()`
and `changePassword()`:

- `EXOP`: the password is sent to the server with the "Password Modify Extended Operation"
  (RFC 3062). The server hashes the password with its own configuration and applies its
  password policy. It is the recommended value if your server supports it (OpenLdap does,
  Active Directory doesn't).
- `AD`: for Microsoft Active Directory. The password is stored into the `unicodePwd`
  attribute, encoded as expected by Active Directory, and the server applies its password
  policy. An encrypted connection is required (`tlsMode` should be `starttls` or `ldaps`).
  See the Active Directory example below.
- `CRYPT`: the password is hashed with SHA-512 crypt (`{CRYPT}$6$...`).
- `SSHA`: salted SHA-1. The salt length is given by `passwordLdapSaltLength` (8 bytes minimum).
- `SHA`, `MD5`, `SMD5`: weak algorithms, kept for compatibility. A warning is logged when they are used.
- empty value (default): the password is not hashed by the library. Use it only if the
  server hashes passwords itself (with the `ppolicy_hash_cleartext` option of OpenLdap for example).

Example of configuration for an OpenLdap server
-----------------------------------------------

A typical OpenLdap directory stores users as `inetOrgPerson` entries, identified
by their `uid` attribute, and groups as `groupOfNames` entries, listing the DN of
their members into the `member` attribute.

```php
$config = array(
    'hostname' => 'ldap.example.com',
    'port' => 389,
    'tlsMode' => 'starttls',
    // if the server certificate is signed by a private CA
    // 'clientTLSCACertificateFile' => '/etc/ssl/certs/example-CA.crt',

    'adminUserDn' => 'cn=admin,dc=example,dc=com',
    'adminPassword' => 'Sup3rP4ssw0rd',

    // users
    'searchUserBaseDN' => 'ou=people,dc=example,dc=com',
    'searchUserFilter' => '(&(objectClass=inetOrgPerson)(uid=%%LOGIN%%))',
    'searchAttributes' => 'uid:login,givenName:firstname,sn:lastname,displayName:realname,mail:email',
    // the DN of the found entry is used to verify the password
    'bindAttribute' => 'dn',

    // groups
    'searchGroupBaseDN' => 'ou=groups,dc=example,dc=com',
    'searchGroupFilter' => '(&(objectClass=groupOfNames)(member=%%USERDN%%))',
    'searchGroupProperty' => 'cn',

    // management of user accounts
    'featureChangePassword' => true,
    'featureCreateUser' => true,
    'featureUpdateUser' => true,
    'featureDeleteUser' => true,
    'newUserDN' => 'uid=%%LOGIN%%,ou=people,dc=example,dc=com',
    'newUserLdapAttributes' => 'objectClass:inetOrgPerson,uid:%%LOGIN%%,userPassword:%%PASSWORD%%,cn:%%REALNAME%%,sn:%%REALNAME%%',
    'passwordLdapHashAlgo' => 'EXOP',
);
```

If your groups are `posixGroup` entries, they list logins instead of DNs into
the `memberUid` attribute. Use then this filter:
`'searchGroupFilter' => '(&(objectClass=posixGroup)(memberUid=%%LOGIN%%))'`.

The admin user must have the rights to read users and groups and, if you enable
modification features, to write into `ou=people`. Remove the `feature*` parameters
if you only need authentication.

Example of configuration for a Microsoft Active Directory server
----------------------------------------------------------------

In Active Directory, users are `user` entries, and the login is usually stored into
the `sAMAccountName` attribute. Users are often spread into several organizational
units, so the base DN is generally the root of the domain. Groups are `group` entries,
listing the DN of their members into the `member` attribute.

```php
$config = array(
    'hostname' => 'dc01.corp.example.com',
    'port' => 636,
    'tlsMode' => 'ldaps',
    // Active Directory certificates are often signed by the CA of the company
    'clientTLSCACertificateFile' => '/etc/ssl/certs/corp-example-CA.crt',

    // a service account having read access to the directory
    'adminUserDn' => 'CN=svc-ldap,OU=Service Accounts,DC=corp,DC=example,DC=com',
    'adminPassword' => 'Sup3rP4ssw0rd',

    // users
    'searchUserBaseDN' => 'DC=corp,DC=example,DC=com',
    // exclude computer accounts and disabled accounts
    'searchUserFilter' => '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%%LOGIN%%)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
    'searchAttributes' => 'sAMAccountName:login,givenName:firstname,sn:lastname,displayName:realname,mail:email,userPrincipalName:',
    // the DN of the found entry is used to verify the password
    'bindAttribute' => 'dn',

    // groups
    'searchGroupBaseDN' => 'DC=corp,DC=example,DC=com',
    'searchGroupFilter' => '(&(objectClass=group)(member=%%USERDN%%))',
    'searchGroupProperty' => 'cn',
);
```

Notes:

- Active Directory accepts STARTTLS on the port 389 too, if it has a certificate:
  `'port' => 389, 'tlsMode' => 'starttls'`.
- To find also groups containing the user indirectly (nested groups), you can use
  the matching rule `LDAP_MATCHING_RULE_IN_CHAIN`:
  `'searchGroupFilter' => '(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=%%USERDN%%))'`.
  This kind of search may be slow on large directories.
- Active Directory accepts also the `userPrincipalName` (`john@corp.example.com`) to
  bind a user. You could set `'bindAttribute' => 'userPrincipalName'`, but using the
  DN is the most reliable.
- Searching from the root of the domain on the port 389 or 636 may return "referrals"
  to other partitions of the directory. If you have performance issues, set a more
  specific `searchUserBaseDN`, or use the Global Catalog (port 3268, or 3269 with ldaps).

### Managing Active Directory accounts

Active Directory does not support the "Password Modify Extended Operation", and stores
passwords into the `unicodePwd` attribute. To change passwords and to create users,
set `passwordLdapHashAlgo` to `AD`, and enable features you need:

```php
$config = array(
    // ... same parameters as above
    'passwordLdapHashAlgo' => 'AD',
    'featureChangePassword' => true,
    'featureCreateUser' => true,
    'featureUpdateUser' => true,
    'featureDeleteUser' => true,
    'newUserDN' => 'cn=%?%,OU=Users,DC=corp,DC=example,DC=com',
    'newUserLdapAttributes' => array(
        'objectClass' => 'user',
        'sAMAccountName' => '%%LOGIN%%',
        'userPrincipalName' => '%%LOGIN%%@corp.example.com',
        'cn' => '%%REALNAME%%',
        'displayName' => '%%REALNAME%%',
        'userAccountControl' => '514',
    ),
);
```

- The service account must have the rights to create, modify and delete users into
  the organizational unit, and the "Reset Password" right.
- A new account is created disabled (`userAccountControl` = 514), then its password is set,
  then the account is enabled: the "disabled" (0x2) and "password not required" (0x20) flags
  are removed from the `userAccountControl` value given into `newUserLdapAttributes`
  (or 512 is set if there is no such value). If the password is refused, for example
  because it does not match the password policy of the domain, the account is deleted
  and an exception is thrown. The reason is written into the logs.
- If `newUserLdapAttributes` is empty, the attributes of the example above are used,
  except `userPrincipalName`.
- `sAMAccountName` is limited to 20 characters, and cannot contain
  `" / \ [ ] : ; | = , + * ? < >`.
- `changePassword()` resets the password with the service account: the password history
  of the domain is not checked by Active Directory.
- A user having child objects (some Exchange objects for example) cannot be deleted
  by `deleteUser()`.
