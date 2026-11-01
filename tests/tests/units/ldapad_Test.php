<?php
/**
 * @author      laurent Jouanneau
 * @copyright   2026 laurent Jouanneau
 * @link        https://www.jelix.org
 * @licence     MIT
 */
use Jelix\Ldap\Ldap;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;

/**
 * Tests ldap library against a Samba server configured as an Active Directory domain controller
 */
class ldapad_Test extends TestCase
{
    protected $ldapProfile = array(
        'hostname' => 'ad.jelix',
        'tlsMode' => 'starttls',
        'port' => 389,
        'adminUserDn' => 'CN=Administrator,CN=Users,DC=ad,DC=jelix',
        'adminPassword' => 'Passjelix-123',
        'searchUserBaseDN' => 'DC=ad,DC=jelix',
        'searchUserFilter' => '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%%LOGIN%%)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
        'searchAttributes' => 'sAMAccountName:login,displayName:realname,mail:email',
        'searchGroupBaseDN' => 'DC=ad,DC=jelix',
        'searchGroupFilter' => '(&(objectClass=group)(member=%%USERDN%%))',
        'searchGroupProperty' => 'cn',
        'featureGroupLoad' => true,
        'passwordLdapHashAlgo' => 'AD',
        'newUserDN' => 'cn=%?%,OU=Guests,DC=ad,DC=jelix',
        'featureCreateUser' => true,
        'featureUpdateUser' => true,
        'featureDeleteUser' => true,
        'featureChangePassword' => true,
        'clientTLSCACertificateFile' => '/customcerts/tests.jelix-CA.crt',
    );

    function testUserExists()
    {
        $ldap = new Ldap($this->ldapProfile, new TestLogger());
        $this->assertTrue($ldap->userExists('john'));
        $this->assertFalse($ldap->userExists('johnny'));
    }

    function testUserExistsLdaps()
    {
        $config = $this->ldapProfile;
        $config['tlsMode'] = 'ldaps';
        $config['port'] = 636;
        $ldap = new Ldap($config, new TestLogger());
        $this->assertTrue($ldap->userExists('john'));
    }

    function testVerifyPassword()
    {
        $ldap = new Ldap($this->ldapProfile, new TestLogger());
        $this->assertFalse($ldap->verifyAuthentication('john', 'wrongpass'));
        $ldapAttr = $ldap->verifyAuthentication('john', 'Passjohn-123');
        $this->assertIsObject($ldapAttr);
        $this->assertEquals('CN=John Doe,OU=People,DC=ad,DC=jelix', $ldapAttr->dn);
        $this->assertEquals(array(
            'login' => 'john',
            'realname' => 'John Doe',
            'email' => 'john@jelix.org',
        ), $ldapAttr->userAttributes);
    }

    function testGetUserWithGroups()
    {
        $ldap = new Ldap($this->ldapProfile, new TestLogger());
        $ldapAttr = $ldap->getUser('john', true);
        $this->assertIsObject($ldapAttr);
        $this->assertEquals(array('testgroup'), $ldapAttr->groups);
    }

    function testCreateUserWithWeakPassword()
    {
        $ldap = new Ldap($this->ldapProfile, new TestLogger());
        try {
            $ldap->createUser('testadweak', 'weak', 'weak@tests.jelix', 'Weak Password');
            $this->fail('the creation of a user with a weak password should fail');
        } catch (\Jelix\Ldap\Exception $e) {
            $this->assertStringContainsString('password', $e->getMessage());
        }
        // the account should have been deleted
        $this->assertFalse($ldap->userExists('testadweak'));
        $config = $this->ldapProfile;
        // the search filter excludes disabled accounts: check there is no disabled account
        $config['searchUserFilter'] = '(&(objectClass=user)(sAMAccountName=%%LOGIN%%))';
        $ldap = new Ldap($config, new TestLogger());
        $this->assertFalse($ldap->userExists('testadweak'));
    }

    function testCreateUser()
    {
        $ldap = new Ldap($this->ldapProfile, new TestLogger());
        $this->assertTrue($ldap->createUser('testad', 'Passrobert-123', 'robert@tests.jelix', 'Robert Dupont'));
        // the account is enabled: the search filter excludes disabled accounts
        $this->assertTrue($ldap->userExists('testad'));

        $ldapAttr = $ldap->verifyAuthentication('testad', 'Passrobert-123');
        $this->assertIsObject($ldapAttr);
        $this->assertEquals('CN=Robert Dupont,OU=Guests,DC=ad,DC=jelix', $ldapAttr->dn);
        $this->assertEquals(array(
            'login' => 'testad',
            'realname' => 'Robert Dupont',
            'email' => 'robert@tests.jelix',
        ), $ldapAttr->userAttributes);
    }

    #[Depends('testCreateUser')]
    function testChangePassword()
    {
        $ldap = new Ldap($this->ldapProfile, new TestLogger());
        $this->assertTrue($ldap->changePassword('testad', 'Passrobert-456'));
        $this->assertFalse($ldap->verifyAuthentication('testad', 'Passrobert-123'));
        $this->assertIsObject($ldap->verifyAuthentication('testad', 'Passrobert-456'));
    }

    #[Depends('testChangePassword')]
    function testChangePasswordWithWeakPassword()
    {
        $ldap = new Ldap($this->ldapProfile, new TestLogger());
        $this->expectException(\Jelix\Ldap\Exception::class);
        $ldap->changePassword('testad', 'weak');
    }

    #[Depends('testChangePassword')]
    function testUpdateUser()
    {
        $ldap = new Ldap($this->ldapProfile, new TestLogger());
        $this->assertTrue($ldap->updateUser('testad', array('mail' => 'robert.dupont@tests.jelix')));
        $ldapAttr = $ldap->getUser('testad');
        $this->assertEquals('robert.dupont@tests.jelix', $ldapAttr->userAttributes['email']);
    }

    #[Depends('testUpdateUser')]
    function testDeleteUser()
    {
        $ldap = new Ldap($this->ldapProfile, new TestLogger());
        $ldapAttr = $ldap->deleteUser('testad');
        $this->assertIsObject($ldapAttr);
        $this->assertEquals('CN=Robert Dupont,OU=Guests,DC=ad,DC=jelix', $ldapAttr->dn);
        $this->assertFalse($ldap->userExists('testad'));
        $this->assertTrue($ldap->deleteUser('testad'));
    }
}
