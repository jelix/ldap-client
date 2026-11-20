# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`jelix/ldap-client`: a standalone PHP (>= 8.2, `ext-ldap`) library to authenticate users against an LDAP directory (OpenLDAP or Active Directory) and to manage their accounts. It came out of the Jelix framework's auth modules but does not depend on Jelix. PSR-4 namespace `Jelix\Ldap\` → `lib/`. Every configuration parameter is documented in `CONFIGURATION.md`. Update that file whenever you add or change a parameter.

## Architecture

- `lib/LdapClient.php` handles connection, search and authentication. It does the following:
  - The constructor merges `$params` with `LdapClient::defaultParameters`, then normalizes and validates them (it parses `searchAttributes`, normalizes the search base DNs and filters, and builds the connection URI). It throws `Jelix\Ldap\Exception` on invalid config. The third argument, `$testMode`, skips the checks that would need a real server or TLS, so unit tests can build the client offline.
  - Public API: `verifyAuthentication()`, `userExists()`, `getUser()`, `testConnection()`, `getFeatures()`/`hasFeature()` (only `FEATURE_GROUP_LOAD` here; all `FEATURE_*` constants are defined in this class) and `getLatestErrorCode()` (`ERROR_*` constants that say why authentication failed).
  - Flow: `_getLinkId()` connects and applies the TLS options (`tlsMode` is `''`, `starttls` or `ldaps`). `_bindLdapAdminUser()` binds with the admin account. `searchLdapUser()` searches every `searchUserBaseDN` with every `searchUserFilter` (`%%LOGIN%%` is replaced by the escaped login) and refuses ambiguous matches. Authentication then re-binds as the user, using the DN or the attribute named by `bindAttribute`.
  - LDAP attributes map to user properties through `searchAttributes` (`ldapAttr:property,...`, parsed by the static `parseSearchAttributes()`). Results are returned as `UserLdapAttributes` (dn, mapped attributes, groups).
- `lib/LdapUserManager.php` (`extends LdapClient`) adds account management: `createUser()`, `updateUser()`, `deleteUser()` and `changePassword()`. Its constructor calls the parent, then applies `userManagerDefaultParameters` and handles the parameters only it uses (`newUserDN`, `newUserLdapAttributes`, `passwordLdapHashAlgo`, `passwordLdapSaltLength` and the management `feature*` flags). `LdapClient` ignores these parameters.
  - There are three password modes. Server-side: the RFC 3062 Password Modify extended operation. Library hashing: SHA-512 crypt, SSHA and older schemes. Active Directory: `passwordLdapHashAlgo=AD` writes `unicodePwd` and manages `userAccountControl`, and it requires TLS.
- `lib/LdapMigration.php` holds static helpers that convert configurations from the old Jelix `ldapdao` and `multiauth` modules to this library's format.

## Tests

Tests need real LDAP servers, so they run in Docker. `tests/docker-compose.yml` defines the containers `jelix_ldap_server` (OpenLDAP, `ldap.jelix`), `jelix_ldap_ad` (Samba AD DC, `ad.jelix`) and `jelix_ldap_php`. The repo is mounted at `/jelixapp`. Run these commands from `tests/`:

```shell
./run-docker build && ./run-docker   # first time (generates test CA/certs if missing); ./run-docker reset removes containers
./appctl composer-install
./appctl ldapreset                    # restore default ldap users (adreset for AD)
./appctl unit-tests                   # all suites: never, allow, demand, ad
./appctl unit-tests-never             # one suite; extra args are passed to phpunit, e.g.:
./appctl unit-tests-never --filter testSomething
```

- Each suite reconfigures the OpenLDAP server's TLS client-certificate policy (`setup-tls-never|allow|demand`) and then runs the matching `tests/tests/phpunit_<mode>.xml`. `phpunit_never.xml` also includes the server-independent tests: `ldapinternals_Test.php` (it calls protected methods through the `LdapClientForTests` subclass of `LdapUserManager` in test mode), `ldapsecurity_Test.php` and `ldapMigration_Test.php`.
- PHPUnit runs with `--process-isolation`, inside the PHP container, from `tests/tests/`.
- Library logs from the tests go to `tests/tests/tmp/ldap_tests.log`.
- The AD test credentials and the password policy are in `tests/README.md`.
