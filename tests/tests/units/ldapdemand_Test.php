<?php
/**
 * @author      laurent Jouanneau
 * @copyright   2019-2026 laurent Jouanneau
 * @link        https://www.jelix.org
 * @licence     MIT
 */
use Jelix\Ldap\Ldap;
use PHPUnit\Framework\TestCase;

/**
 * Tests ldap library against a server that need a client certificate
 */
class ldapdemand_Test  extends TestCase {

    protected $ldapPort = 389;

    protected $ldapTlsMode = '';

    protected $ldapProfileName = 'lpldapdemand';

    protected $ldapProfile = array(
        'hostname'      =>  'ldap.jelix',
        'tlsMode'       => 'starttls',
        'port'          =>  389,
        //'tlsMode'       => 'ldaps',
        //'port'          =>  636,
        'adminUserDn'      =>  'cn=admin,dc=tests,dc=jelix',
        'adminPassword'      =>  'passjelix',
        'searchUserBaseDN' => [
            "ou=people,dc=tests,dc=jelix",
            "ou=admins,dc=tests,dc=jelix", // for user admin
            "ou=guest,dc=tests,dc=jelix", // for guest users
        ],
        'searchUserFilter' => "(&(objectClass=inetOrgPerson)(uid=%%LOGIN%%))",
        'newUserDN' => "uid=%%LOGIN%%,ou=guest,dc=tests,dc=jelix",
        'newUserLdapAttributes' => "objectClass:inetOrgPerson,userPassword:%%PASSWORD%%,cn:%%REALNAME%%,sn:%%REALNAME%%",
        'searchAttributes' => "uid:login,displayName:realname,mail:email",
        'featureCreateUser' => true,
        'featureUpdateUser' => true,
        'featureDeleteUser' => true,
        'featureChangePassword' => true,
        'clientTLSCACertificateFile' => '/customcerts/tests.jelix-CA.crt',
        'clientTLSCertificateFile' => '/customcerts/client.jelix.crt',
        'clientTLSKeyFile' => '/customcerts/client.jelix.key',
    );

    function testUserExistsStartTlsWithoutClientCert() {
        $config = $this->ldapProfile;
        $config['tlsMode'] = 'starttls';
        $config['clientTLSCACertificateFile'] = '';
        $config['clientTLSCertificateFile'] = '';
        $config['clientTLSKeyFile'] = '';
        $this->expectException(\Jelix\Ldap\Exception::class);
        $ldap = new Ldap($config, new TestLogger());
        $this->assertTrue($ldap->userExists('john'));
        $this->assertFalse($ldap->userExists('johnny'));
    }

    function testUserExists() {
        $config = $this->ldapProfile;
        $ldap = new Ldap($config, new TestLogger());

        $this->assertTrue($ldap->userExists('john'));
        $this->assertFalse($ldap->userExists('johnny'));
    }


    function testUserExistsLdaps() {
        $config = $this->ldapProfile;
        $config['tlsMode'] = 'ldaps';
        $config['port'] = 636;

        $ldap = new Ldap($config, new TestLogger());

        $this->assertTrue($ldap->userExists('john'));
        $this->assertFalse($ldap->userExists('johnny'));
    }

    function testUserExistsLdapsWithoutClientCert() {
        $config = $this->ldapProfile;
        $config['tlsMode'] = 'ldaps';
        $config['port'] = 636;
        $config['clientTLSCACertificateFile'] = '';
        $config['clientTLSCertificateFile'] = '';
        $config['clientTLSKeyFile'] = '';
        $this->expectException(\Jelix\Ldap\Exception::class);

        $ldap = new Ldap($config, new TestLogger());

        $this->assertTrue($ldap->userExists('john'));
        $this->assertFalse($ldap->userExists('johnny'));
    }

    function testGetUserOfPeople()
    {
        $config = $this->ldapProfile;

        $ldap = new Ldap($config);
        $ldapAttr = $ldap->getUser('john');
        $this->assertIsObject($ldapAttr);
        $this->assertEquals('uid=john,ou=people,dc=tests,dc=jelix', $ldapAttr->dn);
        $this->assertEquals(array (
            'uid' => 'john',
            'displayName' => 'John Doe',
            'mail' => 'john@jelix.org',
        ), $ldapAttr->ldapAttributes);
        $this->assertEquals(array (
            'login' => 'john',
            'realname' => 'John Doe',
            'email' => 'john@jelix.org',
        ), $ldapAttr->userAttributes);
    }


    function testGetUserOfAdmin()
    {
        $config = $this->ldapProfile;

        $config = $this->ldapProfile;
        //$config['searchUserBaseDN'] = 'ou=admins,dc=tests,dc=jelix';
        $ldap = new Ldap($config);
        $ldapAttr = $ldap->getUser('laurent');
        $this->assertIsObject($ldapAttr);
        $this->assertEquals('uid=laurent,ou=admins,dc=tests,dc=jelix', $ldapAttr->dn);
        $this->assertEquals(array (
            'uid' => 'laurent',
            'displayName' => 'Laurent J',
            'mail' => 'laurent@jelix.org',
        ), $ldapAttr->ldapAttributes);
        $this->assertEquals(array (
            'login' => 'laurent',
            'realname' => 'Laurent J',
            'email' => 'laurent@jelix.org',
        ), $ldapAttr->userAttributes);
    }


    function testVerifyPasswordWithJohn()
    {
        $config = $this->ldapProfile;
        $config['searchGroupFilter'] = '(&(objectClass=groupOfNames)(member=%%USERDN%%))';
        $config['searchGroupProperty'] = 'cn';
        $config['searchGroupBaseDN'] = 'ou=groups,dc=tests,dc=jelix';
        $ldap = new Ldap($config);
        $ldapAttr = $ldap->verifyAuthentication('john', 'passjohn');
        $this->assertIsObject($ldapAttr);
        $this->assertEquals('uid=john,ou=people,dc=tests,dc=jelix', $ldapAttr->dn);
        $this->assertEquals(array (
            'uid' => 'john',
            'displayName' => 'John Doe',
            'mail' => 'john@jelix.org',
        ), $ldapAttr->ldapAttributes);
        $this->assertEquals(array (
            'login' => 'john',
            'realname' => 'John Doe',
            'email' => 'john@jelix.org',
        ), $ldapAttr->userAttributes);
        $this->assertEquals(array('group1', 'group2'), $ldapAttr->groups);
    }


    function testVerifyPasswordWithLaurent()
    {
        $ldap = new Ldap($this->ldapProfile);
        $ldapAttr = $ldap->verifyAuthentication('laurent', 'passlaurent');
        $this->assertIsObject($ldapAttr);
        $this->assertEquals('uid=laurent,ou=admins,dc=tests,dc=jelix', $ldapAttr->dn);
        $this->assertEquals(array (
            'uid' => 'laurent',
            'displayName' => 'Laurent J',
            'mail' => 'laurent@jelix.org',
        ), $ldapAttr->ldapAttributes);
        $this->assertEquals(array (
            'login' => 'laurent',
            'realname' => 'Laurent J',
            'email' => 'laurent@jelix.org',
        ), $ldapAttr->userAttributes);
        $this->assertEquals(null, $ldapAttr->groups);
    }

    function testCreateUser() {
        $ldap = new Ldap($this->ldapProfile);
        $this->assertTrue($ldap->createUser('testldap', 'passrobert', 'robert@tests.jelix', 'Robert Dupont'));
        $this->assertTrue($ldap->userExists('testldap'));
        $ldapAttr = $ldap->verifyAuthentication('testldap', 'passrobert');
        $this->assertIsObject($ldapAttr);
        $this->assertEquals('uid=testldap,ou=guest,dc=tests,dc=jelix', $ldapAttr->dn);
        $this->assertEquals(array (
            'uid' => 'testldap',
            'displayName' => 'Robert Dupont',
            'mail' => 'robert@tests.jelix',
        ), $ldapAttr->ldapAttributes);
        $this->assertEquals(array (
            'login' => 'testldap',
            'realname' => 'Robert Dupont',
            'email' => 'robert@tests.jelix',
        ), $ldapAttr->userAttributes);

    }

    /**
     * @depends testCreateUser
     */
    function testChangePassword() {
        $ldap = new Ldap($this->ldapProfile);
        $this->assertTrue($ldap->changePassword('testldap', 'passrobert2'));
        $this->assertTrue($ldap->userExists('testldap'));
        $this->assertFalse($ldap->verifyAuthentication('testldap', 'passrobert'));
        $ldapAttr = $ldap->verifyAuthentication('testldap', 'passrobert2');
        $this->assertIsObject($ldapAttr);
        $this->assertEquals('uid=testldap,ou=guest,dc=tests,dc=jelix', $ldapAttr->dn);
        $this->assertEquals(array (
            'uid' => 'testldap',
            'displayName' => 'Robert Dupont',
            'mail' => 'robert@tests.jelix',
        ), $ldapAttr->ldapAttributes);
        $this->assertEquals(array (
            'login' => 'testldap',
            'realname' => 'Robert Dupont',
            'email' => 'robert@tests.jelix',
        ), $ldapAttr->userAttributes);

    }

    /**
     * @throws \Jelix\Ldap\Exception
     * @depends testChangePassword
     */
    function testChangeHashedPassword() {
        $config = $this->ldapProfile;
        $config['passwordLdapHashAlgo'] = 'SSHA';
        $ldap = new Ldap($config);
        $this->assertTrue($ldap->changePassword('testldap', 'passroberthashed'));
        $this->assertTrue($ldap->userExists('testldap'));
        $this->assertFalse($ldap->verifyAuthentication('testldap', 'passrobert'));
        $ldapAttr = $ldap->verifyAuthentication('testldap', 'passroberthashed');
        $this->assertIsObject($ldapAttr);
        $this->assertEquals('uid=testldap,ou=guest,dc=tests,dc=jelix', $ldapAttr->dn);
        $this->assertEquals(array (
            'uid' => 'testldap',
            'displayName' => 'Robert Dupont',
            'mail' => 'robert@tests.jelix',
        ), $ldapAttr->ldapAttributes);
        $this->assertEquals(array (
            'login' => 'testldap',
            'realname' => 'Robert Dupont',
            'email' => 'robert@tests.jelix',
        ), $ldapAttr->userAttributes);
    }



    /**
     * @depends testChangePassword
     */
    function testDeleteUser() {
        $ldap = new Ldap($this->ldapProfile);
        $ldapAttr = $ldap->deleteUser('testldap');
        $this->assertIsObject($ldapAttr);
        $this->assertTrue($ldap->deleteUser('testldap'));
        $this->assertEquals('uid=testldap,ou=guest,dc=tests,dc=jelix', $ldapAttr->dn);
        $this->assertEquals(array (
            'uid' => 'testldap',
            'displayName' => 'Robert Dupont',
            'mail' => 'robert@tests.jelix',
        ), $ldapAttr->ldapAttributes);
        $this->assertEquals(array (
            'login' => 'testldap',
            'realname' => 'Robert Dupont',
            'email' => 'robert@tests.jelix',
        ), $ldapAttr->userAttributes);
        $this->assertFalse($ldap->userExists('testldap'));
    }
}
