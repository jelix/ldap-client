This is an application to test the module.

A docker configuration is provided to launch the application into a container.

To launch containers the first time:

```shell
./run-docker build
./run-docker
./appctl ldapreset
```

Then you can launch unit-tests and functional tests with:

```shell
./appctl unit-tests
```

You can execute some commands into the php container, by using this command:

```
./appctl <command>
```

Available commands:

* `reset`: to reinitialize the application 
* `composer-update` and `composer-install`: to update PHP packages
* `ldapreset`: to restore default users in the ldap
* `ldapusers` : to show users defined in the ldap
* `shell`: to have a shell inside the php container
* `ldapshell`: to have a shell inside the ldap container

* `adreset`: to restore default users in the Samba Active Directory server
* `adusers` : to show users and groups defined in the Samba Active Directory server
* `adshell`: to have a shell inside the Samba Active Directory container
* `unit-tests-ad`: to launch only tests against the Samba Active Directory server

Active Directory server
-----------------------

The `samba` container is a Samba server configured as an Active Directory domain
controller, to test the library with `passwordLdapHashAlgo=AD`. It is reachable
with the `ad.jelix` hostname, with STARTTLS on the port 389 or ldaps on the port 636.
Its certificate is signed by the test CA (`docker-conf/certs/tests.jelix-CA.crt`).

- realm `AD.JELIX`, base DN `DC=ad,DC=jelix`
- admin: `CN=Administrator,CN=Users,DC=ad,DC=jelix`, password `Passjelix-123`
- users `john` (`Passjohn-123`) and `jane` (`Passjane-123`) into `OU=People`,
  `john` is member of the group `testgroup`
- new users are created into `OU=Guests`

The domain is provisioned at the first start of the container. To provision it again,
remove the container (`./run-docker reset`).

The password policy of the domain is the default one: passwords should have at
least 7 characters, and contain characters of three categories among uppercase,
lowercase, digits and symbols.
