This is an application to test the module.

A docker configuration is provided to launch the application into a container.

To launch containers the first time:

```
./run-docker build
./run-docker
./appctl ldapreset
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
