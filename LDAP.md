Configuration of the ldap library
================================

Connection configuration
------------------------

Parameters should be given into a PHP array.

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
    'bindUserDN' => "uid=%?%,ou=users,dc=XY,dc=fr",
    'searchAttributes' => "uid:login,givenName:firstname,sn:lastname,mail:email",
    'searchGroupFilter' => "(&(objectClass=posixGroup)(cn=XYZ*)(memberUid=%%LOGIN%%))",
    'searchGroupProperty' => "cn",
    'searchGroupBaseDN' => '',
);
```

First, you should set `hostname`, `port`, which are the name and the port of
the ldap server.

You must also indicate how the connexion should be made. You should indicate 
if you are using the ldap protocol without encryption (`tlsmode=`), the ldap 
protocol with STARTTLS, (`tlsMode=starttls`) or if you are using the ldaps 
protocol (`tlsMode=ldaps`).

If you use the standard port 389, you have the choice between no encryption (empty value)
or `starttls`, for the `tlsMode` setting.

If you are using the port 636, it automatically uses the ldaps protocol. In this
case, setting `tlsMode` to `ldaps` is optional.

Since ldaps is deprecated in OpenLdap, the best solution is to use the port 389
with `tlsMode=starttls`.



Configuration properties for the admin
--------------------------------------

The library needs to query the directory with a user having some rights allowing 
to search a user, to get his attributes, his groups etc... He's called the "admin" 
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

Before to try to authenticate the user against the ldap, the library retrieves
user properties. It uses two configuration parameters : `searchUserFilter`
and `searchAttributes`.

The `searchUserFilter` should contain the ldap query, and a `%%LOGIN%%` placeholder
that will be replaced by the login given by the user.

Example: `searchUserFilter="(&(objectClass=posixAccount)(uid=%%LOGIN%%))"`

You may also indicate the base DN for the search, into `searchUserBaseDN`. Example:
`searchUserBaseDN="ou=ADAM users,o=Microsoft,c=US"`.

Note that you can indicate several search filters, if you have
complex ldap structure. Use `[]` to indicate an item list:

```
searchUserFilter[]="(&(objectClass=posixAccount)(uid=%%LOGIN%%))"
searchUserFilter[]="(&(objectClass=posixAccount)(cn=%%LOGIN%%))"
```

To verify the password, the library needs the DN (Distinguished Name) corresponding 
to the user. It builds the DN from a "template" indicated into the `bindUserDN`
property, and from various data. These data can be the given login or one of
the ldap attributes of the user.

- Building the DN from the login given by the user: bindUserDN should contain
  a DN, with a `%%LOGIN%%` placeholder that will be replaced by the login.

  Example: `bindUserDN="uid=%%LOGIN%%,ou=users,dc=XY,dc=fr"`. If the user
  give `john.smith` as a login, the authentication will be made with the DN
  `bindUserDN="uid=john.smith,ou=users,dc=XY,dc=fr"`.

  For some LDAP, the DN could be a simple string, for example an email. 
  You could then set `bindUserDN="%%LOGIN%%@company.local"`. Or even 
  `bindUserDN="%%LOGIN%%"` if the login can type the full value of
  the DN or an email or else.. (Probably it's not recommended to allow
  a user to type himself its full DN, it can be a security issue)

- Building the DN from one of the ldap attributes of the user. 
  In this case, the library will first query the ldap directory with the 
  `searchUserFilter` filter, to retrieve the user's ldap attributes.
  Then, in bindUserDN, you can indicate a DN where some values will be replaced
  by some attributes values, or you can indicate a single attribute name,
  corresponding to an attribute that contain the full DN of the user.
  
  For the first case, bindUserDn should contain a DN, with some `%?%` placeholders
  that will be replaced by corresponding attributes value. Example:
  `bindUserDN="uid=%?%,ou=users,dc=XY,dc=fr"`. Here it replaces the `%?%` by the
  value of the `uid` attribute readed from the user's attributes.
  The attribute name should be present into the `searchAttributes`
  configuration property, even with no field mapping. Ex: `...,uid,...`. See above.
  
  For the second case, just indicate the attribute name, prefixed with a `$`.
  Example: `bindUserDN="$dn"`. Here it takes the `dn` attribute readed from 
  the search, and use its full value as the DN to login against the ldap server.
  It is useful for some LDAP server like sometimes Active Directory that need a 
  full DN specific for each user.
  The attribute name should be present into the `searchAttributes`
  configuration property, even with no field mapping. Ex: `...,dn:,...`. See above.

Note that you can indicate several dn templates, if you have
complex ldap structure. Use `[]` to indicate an item list:

```
bindUserDN[]="uid=%?%,ou=users,dc=XY,dc=fr"
bindUserDN[]="cn=%?%,ou=users,dc=XY,dc=fr"
```

Retrieving groups of the user
----------------------------------------

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
