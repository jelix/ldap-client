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
without encryption (`tlsMode=`), the ldap protocol with STARTTLS, 
(`tlsMode=starttls`) or if you are using the ldaps protocol (`tlsMode=ldaps`).

If you use the standard port 389, you have the choice between no encryption (empty value)
or `starttls`, for the `tlsMode` setting.

If you are using the port 636, it automatically uses the ldaps protocol. In this
case, setting `tlsMode` to `ldaps` is optional.

Since ldaps is deprecated in OpenLdap, the best solution is to use the port 389
with `tlsMode=starttls`.



Configuration properties for the admin
--------------------------------------

The library needs to query the directory with a user having some rights allowing 
to search a user, to get his attributes, his groups, change a password etc... He's called the "admin" 
in the library.

You must indicate in `adminUserDn` and `adminPassword`, the DN (Distinguished Name) 
and the password of this user. 



Configuration properties for user data
--------------------------------------

Some methods like `getUser` or `verifyAuthentication` loads some ldap attributes
corresponding to the user. 

You should indicate which ldap attributes it can retrieve, and which
database fields that will receive the ldap attributes values.

You indicate such information into the `searchAttributes` property. It is a 
list of assignments, separated by a coma.

An assignment could be written like:

- `<ldap attribute>:<table field>`: the value of the given ldap attribute will be stored into the given table field
- `<ldap attribute>`: the value of the given ldap attribute will be stored into the table field having the same name
- `<ldap attribute>:` (notice the colon at the end): the ldap attribute is retrieved, but no assignment is made. The
  value can be used into other pattern like the `bindUserDN` pattern.

In this example, `searchAttributes="uid:login,givenName,sn:lastname,mail:email,dn:"`:

- the value of the `uid` ldap attribute will be stored into the `login` field 
- the value of the `sn` ldap attribute will be stored into the `lastname` field
- the value of the `givenName` ldap attribute will be stored into a field that
  have the same name, as there is no field name nor `:`.
- there will not be mapping for the `dn` property. There is a `:` without field name.
  It will be readed from ldap, and can be used into the `bindUserDN` DN template.
  (see below).


Configuration properties for authentication
-------------------------------------------

Before to try to authenticate the user against the ldap, the library search and retrieves
user properties. It uses three configuration parameters : `searchUserBaseDN`, `searchUserFilter`
and `searchAttributes`.

The `searchUserBaseDN` parameter indicates the path of the Ldap subtree to search in. 

Example: `'searchUserBaseDN' => "ou=ADAM users,o=Microsoft,c=US"`.

Example: 

The `searchUserFilter` should contain the ldap query, and a `%%LOGIN%%` placeholder
that will be replaced by the login given by the user.

Example: `'searchUserFilter' => "(&(objectClass=posixAccount)(uid=%%LOGIN%%))"`

Note that you can indicate several search filters and several base DN, if you have
complex ldap structure. Use an array instead of a single string:

```
'searchUserBaseDN' => [
  "ou=ADAM users,o=Microsoft,c=US",
  "ou=FOO users,o=Microsoft,c=US"
  ],
'searchUserFilter' => [
  "(&(objectClass=posixAccount)(uid=%%LOGIN%%))",
  "(&(objectClass=posixAccount)(cn=%%LOGIN%%))",
  ]
```

You can have only one `searchUserBaseDN` value and several `searchUserFilter` values. The same base DN will
be used for each filter.

You can have several `searchUserBaseDN` values and only one `searchUserFilter` value. The search will
be done for each base DN, but with the same query.

And you can have  several `searchUserBaseDN` values and several `searchUserFilter` values. In this case
each filter should correspond to each base DN. You must then have same count of `searchUserBaseDN` values and `searchUserFilter` values.
In the previous example, a first search will be made with the filter `(&(objectClass=posixAccount)(uid=%%LOGIN%%))` will be used with
the base DN `ou=ADAM users,o=Microsoft,c=US`. And if the user is not found, a second search will be
made with the filter `(&(objectClass=posixAccount)(cn=%%LOGIN%%))` and 
the base DN `ou=FOO users,o=Microsoft,c=US`.

If there is a result, the DN of the found entry will be used to "bind" to the ldap server with the
password given by the user. (set the `verifyAuthentication()` method).

Retrieving groups of the user
-----------------------------

You may want to retrieve the list of ldap groups where the user is in.

You should then indicate into `searchGroupFilter` the ldap query that will
retrieve the groups of the user.

Example: `searchGroupFilter="(&(objectClass=posixGroup)(member=%%USERDN%%))"`

`%%USERDN%%` is replaced by the user dn.`%%LOGIN%%` is replaced by the login.  
You can also use any ldap attributes you indicate into `searchAttributes`, 
between `%%`. Example: `searchGroupFilter="(&(objectClass=posixGroup)(member=%%givenName%%))"`

With `searchGroupProperty`, you must indicate the ldap attribute that
contains the group name. Ex: `searchGroupProperty="cn"`.

You may also indicate the base DN for the search, into `searchGroupBaseDN`. Example:
`searchGroupBaseDN="ou=Groups,dc=Acme,dc=pt"`.

If you don't want the loading of the groups list, leave `searchGroupFilter` empty.
