Ldap library
======================

A PHP library that simplifies the use of the PHP ldap API, to authenticate users
against an LDAP directory (OpenLdap, Active Directory...) and to manage their accounts.

It was originally developed for the authentication modules of the [Jelix framework](https://jelix.org),
but it does not depend on Jelix and can be used in any PHP application.

Features
--------

**Authentication**

- Verify the login and the password of a user: the library searches the user entry with
  an admin account, then binds to the directory with the DN of the entry and the given password.
- Search users into several subtrees of the directory, with one or several search filters.
- Use the DN of the entry, or the value of one of its attributes, to bind.
- Anonymous and unauthenticated binds are refused.

**User data**

- Check if a user exists.
- Retrieve ldap attributes of a user, and map them to your own user properties
  (e.g. `givenName` → `firstname`). Multi-valued attributes are supported.
- Retrieve the groups of a user, with a configurable search filter.

**Account management** (each feature must be enabled explicitly)

- Create a user, with configurable DN and ldap attributes.
- Update attributes of a user (only attributes declared into the configuration).
- Change the password of a user.
- Delete a user.

**Passwords**

- Password changes made by the server itself, with the "Password Modify Extended Operation" (RFC 3062).
- Or passwords hashed by the library: SHA-512 crypt, SSHA (and older SHA, MD5, SMD5 algorithms).

**Connection and security**

- Connections without encryption, with STARTTLS or with LDAPS.
- With TLS, the certificate of the server is always verified, and TLS 1.2 is the minimum version.
- Custom CA certificate and client certificates.
- Logins and values are escaped before being inserted into filters and DN, to prevent LDAP injections.
- Ambiguous logins (several matching entries) are refused.
- Connection and search timeouts.
- Logging with any PSR-3 logger.

Requirements
------------

- PHP 8.2 or higher
- the PHP `ldap` extension

Installation
------------

```shell
composer require jelix/ldap-authentication
```

Usage
-----

```php
use Jelix\Ldap\Ldap;

$ldap = new Ldap(array(
    'hostname' => 'ldap.example.com',
    'port' => 389,
    'tlsMode' => 'starttls',
    'adminUserDn' => 'cn=admin,dc=example,dc=com',
    'adminPassword' => 'Sup3rP4ssw0rd',
    'searchUserBaseDN' => 'ou=people,dc=example,dc=com',
    'searchUserFilter' => '(&(objectClass=inetOrgPerson)(uid=%%LOGIN%%))',
    'searchAttributes' => 'uid:login,givenName:firstname,sn:lastname,mail:email',
    'searchGroupFilter' => '(&(objectClass=groupOfNames)(member=%%USERDN%%))',
    'searchGroupProperty' => 'cn',
    'searchGroupBaseDN' => 'ou=groups,dc=example,dc=com',
), $logger); // $logger is an optional PSR-3 logger

$user = $ldap->verifyAuthentication($login, $password);
if ($user) {
    // authenticated. Use the login stored into the directory,
    // not the one given by the user.
    echo $user->userAttributes['login'];
    echo $user->userAttributes['email'];
    print_r($user->groups);
}

// other methods
// createUser, updateUser, changePassword and deleteUser need some
// additional parameters (featureCreateUser, newUserDN...)
$ldap->userExists('john');
$ldap->getUser('john', true); // with groups
$ldap->createUser('bob', 'password', 'bob@example.com', 'Bob Smith');
$ldap->updateUser('bob', array('mail' => 'bob.smith@example.com'));
$ldap->changePassword('bob', 'newpassword');
$ldap->deleteUser('bob');
```

Errors (connection failure, search error, ambiguous login...) are reported
with `Jelix\Ldap\Exception` exceptions.

All configuration parameters are described into [CONFIGURATION.md](CONFIGURATION.md).

Tests
-----

Tests are run against an OpenLdap server, in Docker containers.
See [tests/README.md](tests/README.md).

License
-------

MIT. See [LICENCE](LICENCE).
