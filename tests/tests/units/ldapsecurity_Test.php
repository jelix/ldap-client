<?php
/**
 * @author      laurent Jouanneau
 * @copyright   2026 laurent Jouanneau
 * @link        https://www.jelix.org
 * @licence     MIT
 */
use Jelix\Ldap\Ldap;
use Jelix\Ldap\Exception as LdapException;
use PHPUnit\Framework\TestCase;

/**
 * Security tests against the ldap server: injections, ambiguous results, TLS...
 */
class ldapsecurity_Test extends TestCase
{
    protected $ldapProfile = array(
        'hostname'      =>  'ldap.jelix',
        'tlsMode'       => '',
        'port'          =>  389,
        'adminUserDn'      =>  'cn=admin,dc=tests,dc=jelix',
        'adminPassword'      =>  'passjelix',
        'searchUserBaseDN' => [
            "ou=people,dc=tests,dc=jelix",
            "ou=admins,dc=tests,dc=jelix",
            "ou=guest,dc=tests,dc=jelix",
        ],
        'searchUserFilter' => "(&(objectClass=inetOrgPerson)(uid=%%LOGIN%%))",
        'newUserDN' => "uid=%%LOGIN%%,ou=guest,dc=tests,dc=jelix",
        'newUserLdapAttributes' => "objectClass:inetOrgPerson,userPassword:%%PASSWORD%%,cn:%%REALNAME%%,sn:%%REALNAME%%",
        'searchAttributes' => "uid:login,displayName:realname,mail:email",
        'featureCreateUser' => true,
        'featureUpdateUser' => true,
        'featureDeleteUser' => true,
        'featureChangePassword' => true,
        'clientTLSCACertificateFile' => '/customcerts/tests.jelix-CA.crt'
    );

    protected function getLdap(array $config = array()): Ldap
    {
        return new Ldap(array_merge($this->ldapProfile, $config), new TestLogger());
    }

    /**
     * Read the userPassword attribute of a user, as stored into the directory
     */
    protected function getStoredPassword(string $login): string
    {
        $ldap = $this->getLdap(array('searchAttributes' => 'uid:login,userPassword:'));
        $attrs = $ldap->getUser($login);
        $this->assertNotNull($attrs);
        return $attrs->ldapAttributes['userPassword'];
    }

    // ---------------------- injection into the user search filter

    function testWildcardLoginIsNotFound()
    {
        $ldap = $this->getLdap();
        $this->assertTrue($ldap->userExists('john'));
        $this->assertFalse($ldap->userExists('*'));
        $this->assertFalse($ldap->userExists('jo*'));
        $this->assertNull($ldap->getUser('*'));
        $this->assertNull($ldap->getUser('*)(uid=john'));
        $this->assertFalse($ldap->userExists('john)(|(uid=*'));
    }

    function testAuthenticationWithInjectedLoginFails()
    {
        $ldap = $this->getLdap();
        $this->assertFalse($ldap->verifyAuthentication('*', 'passjohn'));
        $this->assertFalse($ldap->verifyAuthentication('jo*', 'passjohn'));
        $this->assertFalse($ldap->verifyAuthentication('john)(uid=*', 'passjohn'));
        $this->assertFalse($ldap->verifyAuthentication("john\0", 'passjohn'));
        $this->assertIsObject($ldap->verifyAuthentication('john', 'passjohn'));
    }

    function testWriteOperationsWithInjectedLogin()
    {
        $ldap = $this->getLdap();
        $this->assertTrue($ldap->deleteUser('*'), 'nobody should be deleted');
        $this->assertFalse($ldap->changePassword('*', 'hacked'));
        $this->assertFalse($ldap->changePassword('jo*', 'hacked'));
        $this->assertFalse($ldap->updateUser('*', array('mail' => 'hacker@example.com')));

        $this->assertTrue($ldap->userExists('john'));
        $this->assertTrue($ldap->userExists('jane'));
        $this->assertIsObject($ldap->verifyAuthentication('john', 'passjohn'));
        $this->assertEquals('john@jelix.org', $ldap->getUser('john')->ldapAttributes['mail']);
    }

    function testLoginWithSpecialCharsCanBeUsed()
    {
        $ldap = $this->getLdap();
        $login = 'o*brian (test)\\';
        try {
            $this->assertTrue($ldap->createUser($login, 'passbrian', 'brian@tests.jelix', 'Brian'));
            $this->assertTrue($ldap->userExists($login));
            $this->assertFalse($ldap->userExists('o*'));
            $this->assertIsObject($ldap->verifyAuthentication($login, 'passbrian'));
        } finally {
            $ldap->deleteUser($login);
        }
        $this->assertFalse($ldap->userExists($login));
    }

    // ---------------------- ambiguous results

    function testAmbiguousLoginIsRejected()
    {
        // john and jane match this filter
        $ldap = $this->getLdap(array(
            'searchUserFilter' => "(&(objectClass=inetOrgPerson)(|(uid=%%LOGIN%%)(sn=*Doe)))",
        ));
        $this->expectException(LdapException::class);
        $ldap->verifyAuthentication('john', 'passjohn');
    }

    function testAmbiguousLoginIsRejectedForDeletion()
    {
        $ldap = $this->getLdap(array(
            'searchUserFilter' => "(&(objectClass=inetOrgPerson)(|(uid=%%LOGIN%%)(sn=*Doe)))",
        ));
        try {
            $ldap->deleteUser('jane');
            $this->fail('An exception should be thrown');
        } catch (LdapException $e) {
        }
        $this->assertTrue($this->getLdap()->userExists('john'));
        $this->assertTrue($this->getLdap()->userExists('jane'));
    }

    // ---------------------- injection into the DN of a new user

    function testCreateUserWithDnInjection()
    {
        $ldap = $this->getLdap();
        $login = 'evil,ou=admins';
        try {
            $this->assertTrue($ldap->createUser($login, 'passevil', 'evil@tests.jelix', 'Evil'));
            $attrs = $ldap->getUser($login);
            $this->assertIsObject($attrs);
            $this->assertEquals($login, $attrs->userAttributes['login']);
            $this->assertStringEndsWith(',ou=guest,dc=tests,dc=jelix', $attrs->dn);
            $this->assertEquals(1, substr_count($attrs->dn, 'ou='), 'only one ou should be in the DN');
            $this->assertFalse($ldap->userExists('evil'));
        } finally {
            $ldap->deleteUser($login);
        }
    }

    function testCreateUserWithDnInjectionIntoAttribute()
    {
        $ldap = $this->getLdap(array(
            'newUserDN' => "uid=%?%,ou=guest,dc=tests,dc=jelix",
            'newUserLdapAttributes' => "objectClass:inetOrgPerson,uid:%%LOGIN%%,userPassword:%%PASSWORD%%,cn:%%REALNAME%%,sn:%%REALNAME%%",
        ));
        $login = 'evil2+cn=admin';
        try {
            $this->assertTrue($ldap->createUser($login, 'passevil', 'evil@tests.jelix', 'Evil'));
            $attrs = $ldap->getUser($login);
            $this->assertIsObject($attrs);
            $this->assertEquals($login, $attrs->userAttributes['login']);
            $this->assertStringEndsWith(',ou=guest,dc=tests,dc=jelix', $attrs->dn);
        } finally {
            $ldap->deleteUser($login);
        }
    }

    // ---------------------- DN used for the bind

    function testBindAttributeMissing()
    {
        // john does not have a description attribute
        $ldap = $this->getLdap(array('bindAttribute' => 'description'));
        $this->assertFalse($ldap->verifyAuthentication('john', 'anypassword'));
        $this->assertFalse($ldap->verifyAuthentication('john', 'passjohn'));
    }

    function testBindAttributeIsCaseInsensitive()
    {
        // seeAlso of john contains its DN
        $ldap = $this->getLdap(array('bindAttribute' => 'SEEALSO'));
        $this->assertIsObject($ldap->verifyAuthentication('john', 'passjohn'));
        $this->assertFalse($ldap->verifyAuthentication('john', 'wrongpassword'));
    }

    function testAdminWithoutPasswordIsRefused()
    {
        $ldap = $this->getLdap(array('adminPassword' => ''));
        $this->expectException(LdapException::class);
        $ldap->userExists('john');
    }

    // ---------------------- group search

    function testGroupsOfUserHavingSpecialCharsIntoItsDn()
    {
        $ldap = $this->getLdap(array(
            'searchGroupFilter' => '(&(objectClass=groupOfNames)(member=%%USERDN%%))',
            'searchGroupProperty' => 'cn',
            'searchGroupBaseDN' => 'ou=groups,dc=tests,dc=jelix',
        ));
        $attrs = $ldap->verifyAuthentication('pierre', 'passpierre');
        $this->assertIsObject($attrs);
        $this->assertEquals('cn=Pierre (Paris)\2C Jr,ou=people,dc=tests,dc=jelix', $attrs->dn);
        $this->assertEquals(array('group3'), $attrs->groups);
    }

    function testAttributesAreEscapedIntoGroupFilter()
    {
        // the description of pierre is "group*". It should not match all groups.
        $ldap = $this->getLdap(array(
            'searchAttributes' => "uid:login,displayName:realname,mail:email,description:",
            'searchGroupFilter' => '(&(objectClass=groupOfNames)(cn=%%description%%))',
            'searchGroupProperty' => 'cn',
            'searchGroupBaseDN' => 'ou=groups,dc=tests,dc=jelix',
        ));
        $attrs = $ldap->getUser('pierre', true);
        $this->assertIsObject($attrs);
        $this->assertEquals('group*', $attrs->ldapAttributes['description']);
        $this->assertNull($attrs->groups);
    }

    // ---------------------- errors during the search

    function testNonExistentBaseDnIsIgnored()
    {
        $ldap = $this->getLdap(array(
            'searchUserBaseDN' => array('ou=nothere,dc=tests,dc=jelix', 'ou=people,dc=tests,dc=jelix'),
        ));
        $this->assertTrue($ldap->userExists('john'));
        $this->assertFalse($ldap->userExists('laurent'));
    }

    function testSearchErrorThrowsAnException()
    {
        $ldap = $this->getLdap(array('searchUserFilter' => '(uid=%%LOGIN%%'));
        $this->expectException(LdapException::class);
        $ldap->userExists('john');
    }

    function testSearchErrorDuringDeletionThrowsAnException()
    {
        $ldap = $this->getLdap(array('searchUserFilter' => '(uid=%%LOGIN%%'));
        $this->expectException(LdapException::class);
        $ldap->deleteUser('john');
    }

    // ---------------------- TLS

    function testUnencryptedConnectionIsStillPossible()
    {
        $this->assertTrue($this->getLdap(array('tlsMode' => ''))->userExists('john'));
        $this->assertTrue($this->getLdap(array('tlsMode' => 'none'))->userExists('john'));
    }

    function testTlsModeIsCaseInsensitive()
    {
        $this->assertTrue($this->getLdap(array('tlsMode' => 'StartTLS'))->userExists('john'));
    }

    function testInvalidTlsModeIsRefused()
    {
        $this->expectException(LdapException::class);
        $this->getLdap(array('tlsMode' => 'yes'));
    }

    function testServerCertificateIsAlwaysVerified()
    {
        // even if the environment disables the verification of the certificate,
        // the library must verify it. The CA of the test server is not known here.
        putenv('LDAPTLS_REQCERT=never');
        $ldap = $this->getLdap(array(
            'tlsMode' => 'starttls',
            'clientTLSCACertificateFile' => '',
        ));
        $this->expectException(LdapException::class);
        $ldap->userExists('john');
    }

    function testNetworkTimeout()
    {
        // non-routable address
        $ldap = $this->getLdap(array(
            'hostname' => '10.255.255.1',
            'networkTimeout' => 2,
        ));
        $start = microtime(true);
        try {
            $ldap->userExists('john');
            $this->fail('An exception should be thrown');
        } catch (LdapException $e) {
        }
        $this->assertLessThan(10, microtime(true) - $start);
    }

    // ---------------------- passwords

    function testCryptAndExopPasswords()
    {
        $ldap = $this->getLdap();
        $login = 'testsecu';
        try {
            $this->assertTrue($ldap->createUser($login, 'pass1', 'secu@tests.jelix', 'Secu'));

            $ldapCrypt = $this->getLdap(array('passwordLdapHashAlgo' => 'CRYPT'));
            $this->assertTrue($ldapCrypt->changePassword($login, 'pass2'));
            $this->assertStringStartsWith('{CRYPT}$6$', $this->getStoredPassword($login));
            $this->assertFalse($ldapCrypt->verifyAuthentication($login, 'pass1'));
            $this->assertIsObject($ldapCrypt->verifyAuthentication($login, 'pass2'));

            // with EXOP, the server hashes the password
            $ldapExop = $this->getLdap(array('passwordLdapHashAlgo' => 'EXOP'));
            $this->assertTrue($ldapExop->changePassword($login, 'pass3'));
            $stored = $this->getStoredPassword($login);
            $this->assertStringStartsWith('{', $stored);
            $this->assertStringNotContainsString('pass3', $stored);
            $this->assertFalse($ldapExop->verifyAuthentication($login, 'pass2'));
            $this->assertIsObject($ldapExop->verifyAuthentication($login, 'pass3'));
        } finally {
            $ldap->deleteUser($login);
        }
    }

    function testCreateUserWithExop()
    {
        $ldap = $this->getLdap(array('passwordLdapHashAlgo' => 'EXOP'));
        $login = 'testsecuexop';
        try {
            $this->assertTrue($ldap->createUser($login, 'passexop', 'secu@tests.jelix', 'Secu'));
            $stored = $this->getStoredPassword($login);
            $this->assertStringStartsWith('{', $stored);
            $this->assertStringNotContainsString('passexop', $stored);
            $this->assertIsObject($ldap->verifyAuthentication($login, 'passexop'));
        } finally {
            $ldap->deleteUser($login);
        }
    }

    // ---------------------- updateUser

    function testUpdateUserWithForbiddenAttributes()
    {
        $ldap = $this->getLdap();
        foreach (array('userPassword', 'objectClass', 'description') as $attr) {
            try {
                $ldap->updateUser('john', array($attr => 'foo'));
                $this->fail('attribute '.$attr.' should not be modified');
            } catch (LdapException $e) {
            }
        }
        $this->assertIsObject($ldap->verifyAuthentication('john', 'passjohn'));
    }

    function testUpdateUserWithAllowedAttributes()
    {
        $ldap = $this->getLdap();
        try {
            $this->assertTrue($ldap->updateUser('john', array('MAIL' => 'john2@jelix.org')));
            $this->assertEquals('john2@jelix.org', $ldap->getUser('john')->ldapAttributes['mail']);
        } finally {
            $ldap->updateUser('john', array('mail' => 'john@jelix.org'));
        }
        $this->assertEquals('john@jelix.org', $ldap->getUser('john')->ldapAttributes['mail']);
        $this->assertFalse($ldap->updateUser('johnny', array('mail' => 'john@jelix.org')));
    }

    // ---------------------- login normalization

    function testLoginWithSpacesOrControlCharsIsRefused()
    {
        $ldap = $this->getLdap();
        $this->assertTrue($ldap->userExists(' john'));
        $this->assertTrue($ldap->userExists('john '));
        $this->assertFalse($ldap->userExists("john\n"));
        $this->assertIsObject($ldap->verifyAuthentication(' john', 'passjohn'));
        $this->assertFalse($ldap->verifyAuthentication("john\r\n", 'passjohn'));

        $this->expectException(LdapException::class);
        $ldap->createUser(' bob', 'passbob', 'bob@tests.jelix');
    }

    function testRealLoginIsReturned()
    {
        $ldap = $this->getLdap();
        $attrs = $ldap->verifyAuthentication('JOHN', 'passjohn');
        $this->assertIsObject($attrs);
        $this->assertEquals('john', $attrs->userAttributes['login']);
    }

    // ---------------------- attributes

    function testMultiValuedAttributes()
    {
        $attrs = $this->getLdap()->getUser('pierre');
        $this->assertIsObject($attrs);
        $this->assertEquals('pierre@jelix.org', $attrs->ldapAttributes['mail']);
        $this->assertEquals(array('pierre@jelix.org', 'pierre.paris@jelix.org'), $attrs->ldapAttributesValues['mail']);
        $this->assertEquals('pierre@jelix.org', $attrs->userAttributes['email']);
    }

    function testAttributesMappingIsCaseInsensitive()
    {
        $ldap = $this->getLdap(array('searchAttributes' => "UID:login,DISPLAYNAME:realname,Mail:email"));
        $attrs = $ldap->getUser('john');
        $this->assertEquals(array(
            'UID' => 'john',
            'DISPLAYNAME' => 'John Doe',
            'Mail' => 'john@jelix.org',
        ), $attrs->ldapAttributes);
        $this->assertEquals(array(
            'login' => 'john',
            'realname' => 'John Doe',
            'email' => 'john@jelix.org',
        ), $attrs->userAttributes);
    }

    function testCreateUserWithDefaultNewUserAttributes()
    {
        $config = $this->ldapProfile;
        unset($config['newUserLdapAttributes']);
        $ldap = new Ldap($config, new TestLogger());
        $login = 'testsecudefault';
        try {
            $this->assertTrue($ldap->createUser($login, 'passdefault', 'default@tests.jelix', 'Default User'));
            $this->assertIsObject($ldap->verifyAuthentication($login, 'passdefault'));
        } finally {
            $ldap->deleteUser($login);
        }
    }

    function testCreateUserWithPlaceholdersAndMultiValues()
    {
        $ldap = $this->getLdap(array(
            'searchAttributes' => "uid:login,displayName:realname,mail:email,description:,objectClass:,cn:",
            'newUserLdapAttributes' => array(
                'objectClass' => array('inetOrgPerson', 'organizationalPerson'),
                'userPassword' => '%%PASSWORD%%',
                'cn' => '%%REALNAME%%',
                'sn' => '%%REALNAME%%',
                'description' => 'Account of %%LOGIN%%: created by tests',
            ),
        ));
        $login = 'testsecuplaceholder';
        try {
            // placeholders into values given by the user should not be replaced
            $this->assertTrue($ldap->createUser($login, 'passplaceholder', 'ph@tests.jelix', 'Name %%LOGIN%%'));
            $attrs = $ldap->getUser($login);
            $this->assertIsObject($attrs);
            $this->assertEquals('Account of testsecuplaceholder: created by tests', $attrs->ldapAttributes['description']);
            $this->assertEquals('Name %%LOGIN%%', $attrs->ldapAttributes['cn']);
            $this->assertContains('organizationalPerson', $attrs->ldapAttributesValues['objectClass']);
            $this->assertIsObject($ldap->verifyAuthentication($login, 'passplaceholder'));
        } finally {
            $ldap->deleteUser($login);
        }
    }
}
