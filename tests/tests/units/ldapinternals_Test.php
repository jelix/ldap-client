<?php
/**
 * @author      laurent Jouanneau
 * @copyright   2026 laurent Jouanneau
 * @link        https://www.jelix.org
 * @licence     MIT
 */
use Jelix\Ldap\LdapClient;
use Jelix\Ldap\UserLdapAttributes;
use LDAP\Connection;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;

/**
 * Gives access to protected methods of the Ldap class
 */
class LdapClientForTests extends LdapClient
{
    public function __call($name, $arguments)
    {
        return $this->$name(...$arguments);
    }

    public function getParameter($name)
    {
        return $this->parameters[$name];
    }

    public function testIsValidLogin($login)
    {
        return $this->isValidLogin($login);
    }

    public function testCreateDn(string $dnPattern, string $login, array $userLdapAttributes): false|string
    {
        return $this->createDn($dnPattern, $login, $userLdapAttributes);
    }

    public function testReadLdapAttributes(string $dn, array $origLdapAttributes): UserLdapAttributes
    {
        return $this->readLdapAttributes($dn, $origLdapAttributes);
    }

    public function testHashPassword(string $password) : string
    {
        return $this->hashPassword($password);
    }

    public function testEncodeActiveDirectoryPassword(string $password) : string
    {
        return $this->encodeActiveDirectoryPassword($password);
    }

    public function testcheckUpdatableAttributes(array $attributes): void
    {
        $this->checkUpdatableAttributes($attributes);
    }

    public function testLog(int $type, string $message, ?Connection $connect = null)
    {
        $this->log($type, $message, $connect);
    }
}

class ArrayLogger extends AbstractLogger
{
    public $messages = array();

    public function log($level, $message, array $context = array())
    {
        $this->messages[] = array($level, $message);
    }
}

/**
 * Tests of internal methods of the Ldap class, which don't need an ldap server
 */
class ldapinternals_Test extends TestCase
{
    protected $config = array(
        'hostname' => 'ldap.jelix',
        'adminUserDn' => 'cn=admin,dc=tests,dc=jelix',
        'adminPassword' => 'passjelix',
        'searchUserBaseDN' => 'ou=people,dc=tests,dc=jelix',
        'searchUserFilter' => '(&(objectClass=inetOrgPerson)(uid=%%LOGIN%%))',
        'searchAttributes' => 'uid:login,displayName:realname,mail:email',
    );

    function testSearchAttributesParser()
    {
        $attributes = 'UID:login,displayname:realname,mail:email,cn:,foo,givenName:firstname';
        $result = LdapClient::parseSearchAttributes($attributes);
        $this->assertEquals(array(
            'UID' => 'login',
            'displayname' => 'realname',
            'mail' => 'email',
            'cn' => '',
            'foo' => 'foo',
            'givenName' => 'firstname'
        ), $result);
    }

    function testTlsModeValues()
    {
        foreach (array(
                     '' => '',
                     'none' => '',
                     'NONE' => '',
                     'starttls' => 'starttls',
                     'StartTLS' => 'starttls',
                     ' ldaps ' => 'ldaps',
                 ) as $value => $expected) {
            $config = $this->config;
            $config['tlsMode'] = $value;
            $ldap = new LdapClientForTests($config);
            $this->assertEquals($expected, $ldap->getParameter('tlsMode'), 'tlsMode='.$value);
        }
    }

    function testInvalidTlsMode()
    {
        $config = $this->config;
        $config['tlsMode'] = 'tls';
        $this->expectException(\Jelix\Ldap\Exception::class);
        new LdapClient($config);
    }

    function testNewUserLdapAttributesAsString()
    {
        $config = $this->config;
        $config['newUserLdapAttributes'] = "objectClass:inetOrgPerson, objectClass:organizationalPerson,".
            "userPassword:%%PASSWORD%%,description:Account of %%LOGIN%%: created by tests,cn:%%REALNAME%%";
        $ldap = new LdapClientForTests($config);
        $this->assertEquals(array(
            'objectClass' => array('inetOrgPerson', 'organizationalPerson'),
            'userPassword' => '%%PASSWORD%%',
            'description' => 'Account of %%LOGIN%%: created by tests',
            'cn' => '%%REALNAME%%',
        ), $ldap->getParameter('newUserLdapAttributes'));
    }

    function testNewUserLdapAttributesAsArray()
    {
        $config = $this->config;
        $config['newUserLdapAttributes'] = array(
            'objectClass' => array('inetOrgPerson', 'organizationalPerson'),
            'description' => 'Account, of %%LOGIN%%',
        );
        $ldap = new LdapClientForTests($config);
        $this->assertEquals($config['newUserLdapAttributes'], $ldap->getParameter('newUserLdapAttributes'));
    }

    function testDefaultNewUserLdapAttributesHaveRequiredAttributes()
    {
        $ldap = new LdapClientForTests($this->config);
        $attributes = $ldap->getParameter('newUserLdapAttributes');
        $this->assertArrayHasKey('cn', $attributes);
        $this->assertArrayHasKey('sn', $attributes);
    }

    function testIsValidLogin()
    {
        $ldap = new LdapClientForTests($this->config);
        $this->assertTrue($ldap->testIsValidLogin('john'));
        $this->assertTrue($ldap->testIsValidLogin('john.doe@example.com'));
        $this->assertTrue($ldap->testIsValidLogin('jean dupont'));
        $this->assertTrue($ldap->testIsValidLogin('*')); // it will be escaped
        $this->assertFalse($ldap->testIsValidLogin(''));
        $this->assertFalse($ldap->testIsValidLogin(' john'));
        $this->assertFalse($ldap->testIsValidLogin('john '));
        $this->assertFalse($ldap->testIsValidLogin("john\n"));
        $this->assertFalse($ldap->testIsValidLogin("jo\nhn"));
        $this->assertFalse($ldap->testIsValidLogin("jo\0hn"));
        $this->assertFalse($ldap->testIsValidLogin("jo\x7Fhn"));
    }

    function testCreateDnEscapesLogin()
    {
        $ldap = new LdapClientForTests($this->config);
        $this->assertEquals(
            'uid=evil\2cou\3dadmins,ou=guest,dc=tests,dc=jelix',
            $ldap->testCreateDn('uid=%%LOGIN%%,ou=guest,dc=tests,dc=jelix', 'evil,ou=admins', array())
        );
        $this->assertEquals(
            'uid=\20a\2bb\5c\23,ou=guest,dc=tests,dc=jelix',
            $ldap->testCreateDn('uid=%%LOGIN%%,ou=guest,dc=tests,dc=jelix', ' a+b\\#', array())
        );
    }

    function testCreateDnEscapesAttributeValues()
    {
        $ldap = new LdapClientForTests($this->config);
        $this->assertEquals(
            'cn=Doe\2c John,ou=guest,dc=tests,dc=jelix',
            $ldap->testCreateDn('cn=%?%,ou=guest,dc=tests,dc=jelix', 'john', array('cn' => 'Doe, John'))
        );
        $this->assertEquals(
            'cn=Doe,ou=guest,dc=tests,dc=jelix',
            $ldap->testCreateDn('cn=%?%,ou=guest,dc=tests,dc=jelix', 'john', array('cn' => array('Doe', 'Other')))
        );
        $this->assertFalse(
            $ldap->testCreateDn('cn=%?%,ou=guest,dc=tests,dc=jelix', 'john', array())
        );
    }

    function testCreateDnFromAttribute()
    {
        $ldap = new LdapClientForTests($this->config);
        $this->assertEquals(
            'uid=john,ou=guest,dc=tests,dc=jelix',
            $ldap->testCreateDn(' $mydn ', 'john', array('mydn' => 'uid=john,ou=guest,dc=tests,dc=jelix'))
        );
    }

    function testReadLdapAttributes()
    {
        $config = $this->config;
        $config['searchAttributes'] = 'UID:login,displayname:realname,mail:email,givenName:firstname';
        $ldap = new LdapClientForTests($config);
        // structure returned by ldap_get_attributes
        $attrs = $ldap->testReadLdapAttributes('uid=john,ou=people,dc=tests,dc=jelix', array(
            'uid' => array('john', 'count' => 1),
            0 => 'uid',
            'displayName' => array('John Doe', 'count' => 1),
            1 => 'displayName',
            'mail' => array('john@jelix.org', 'john.doe@jelix.org', 'count' => 2),
            2 => 'mail',
            'count' => 3,
        ));
        $this->assertEquals('uid=john,ou=people,dc=tests,dc=jelix', $attrs->dn);
        $this->assertEquals(array(
            'UID' => 'john',
            'displayname' => 'John Doe',
            'mail' => 'john@jelix.org',
        ), $attrs->ldapAttributes);
        $this->assertEquals(array(
            'UID' => array('john'),
            'displayname' => array('John Doe'),
            'mail' => array('john@jelix.org', 'john.doe@jelix.org'),
        ), $attrs->ldapAttributesValues);
        $this->assertEquals(array(
            'login' => 'john',
            'realname' => 'John Doe',
            'email' => 'john@jelix.org',
            'firstname' => '',
        ), $attrs->userAttributes);
    }

    function testHashPasswordSSHA()
    {
        $config = $this->config;
        $config['passwordLdapHashAlgo'] = 'SSHA';
        $ldap = new LdapClientForTests($config);
        $hash = $ldap->testHashPassword('secret');
        $this->assertStringStartsWith('{SSHA}', $hash);
        $raw = base64_decode(substr($hash, 6));
        $this->assertEquals(28, strlen($raw), '20 bytes of SHA1 + 8 bytes of salt');
        $salt = substr($raw, 20);
        $this->assertEquals(sha1('secret'.$salt, true), substr($raw, 0, 20));
        $this->assertNotEquals($hash, $ldap->testHashPassword('secret'), 'salt should be random');
    }

    function testHashPasswordSaltLength()
    {
        $config = $this->config;
        $config['passwordLdapHashAlgo'] = 'SSHA';
        $config['passwordLdapSaltLength'] = 16;
        $ldap = new LdapClientForTests($config);
        $this->assertEquals(36, strlen(base64_decode(substr($ldap->testHashPassword('secret'), 6))));

        // too short salt are not allowed
        $config['passwordLdapSaltLength'] = 2;
        $ldap = new LdapClientForTests($config);
        $this->assertEquals(28, strlen(base64_decode(substr($ldap->testHashPassword('secret'), 6))));
    }

    function testHashPasswordCrypt()
    {
        $config = $this->config;
        $config['passwordLdapHashAlgo'] = 'CRYPT';
        $ldap = new LdapClientForTests($config);
        $hash = $ldap->testHashPassword('secret');
        $this->assertStringStartsWith('{CRYPT}$6$rounds=50000$', $hash);
        $hash = substr($hash, 7);
        $this->assertTrue(hash_equals($hash, crypt('secret', $hash)));
        $this->assertFalse(hash_equals($hash, crypt('secret2', $hash)));
    }

    function testHashPasswordWeakAlgorithmsAreLogged()
    {
        foreach (array('SHA', 'MD5', 'SMD5') as $algo) {
            $config = $this->config;
            $config['passwordLdapHashAlgo'] = $algo;
            $logger = new ArrayLogger();
            $ldap = new LdapClientForTests($config, $logger);
            $this->assertStringStartsWith('{'.$algo.'}', $ldap->testHashPassword('secret'));
            $this->assertCount(1, $logger->messages);
            $this->assertEquals('warning', $logger->messages[0][0]);
        }
        $this->assertEquals('{SHA}'.base64_encode(sha1('secret', true)), (new LdapClientForTests(
            array_merge($this->config, array('passwordLdapHashAlgo' => 'SHA'))))->testHashPassword('secret'));
    }

    function testHashPasswordExopIsNotAllowed()
    {
        $config = $this->config;
        $config['passwordLdapHashAlgo'] = 'EXOP';
        $ldap = new LdapClientForTests($config);
        $this->expectException(\Jelix\Ldap\Exception::class);
        $ldap->testHashPassword('secret');
    }

    function testFeatureGroupLoad()
    {
        $config = $this->config;
        $config['searchGroupFilter'] = '(&(objectClass=groupOfNames)(member=%%USERDN%%))';
        $config['searchGroupProperty'] = 'cn';
        $config['searchGroupBaseDN'] = 'ou=groups,dc=tests,dc=jelix';

        // group parameters without featureGroupLoad: groups are not loaded
        $ldap = new LdapClientForTests($config);
        $this->assertEquals(0, $ldap->getFeatures() & LdapClient::FEATURE_GROUP_LOAD);

        $config['featureGroupLoad'] = true;
        $ldap = new LdapClientForTests($config);
        $this->assertEquals(LdapClient::FEATURE_GROUP_LOAD, $ldap->getFeatures() & LdapClient::FEATURE_GROUP_LOAD);
    }

    function testFeatureGroupLoadNeedsGroupParameters()
    {
        foreach (array('searchGroupFilter', 'searchGroupProperty', 'searchGroupBaseDN') as $name) {
            $config = $this->config;
            $config['featureGroupLoad'] = true;
            $config['searchGroupFilter'] = '(&(objectClass=groupOfNames)(member=%%USERDN%%))';
            $config['searchGroupProperty'] = 'cn';
            $config['searchGroupBaseDN'] = 'ou=groups,dc=tests,dc=jelix';
            $config[$name] = ' ';
            try {
                new LdapClient($config);
                $this->fail('an exception should be thrown when '.$name.' is empty');
            } catch (\Jelix\Ldap\Exception $e) {
                $this->assertStringContainsString($name, $e->getMessage());
            }
        }
    }

    function testHashPasswordADIsNotAllowed()
    {
        $config = $this->config;
        $config['tlsMode'] = 'starttls';
        $config['passwordLdapHashAlgo'] = 'AD';
        $ldap = new LdapClientForTests($config);
        $this->expectException(\Jelix\Ldap\Exception::class);
        $ldap->testHashPassword('secret');
    }

    function testADNeedsEncryption()
    {
        foreach (array('starttls', 'ldaps') as $tlsMode) {
            $config = $this->config;
            $config['tlsMode'] = $tlsMode;
            $config['passwordLdapHashAlgo'] = 'AD';
            $ldap = new LdapClientForTests($config);
            $this->assertEquals($tlsMode, $ldap->getParameter('tlsMode'));
        }

        $config = $this->config;
        $config['tlsMode'] = '';
        $config['passwordLdapHashAlgo'] = 'ad';
        $this->expectException(\Jelix\Ldap\Exception::class);
        new LdapClient($config);
    }

    function testADDefaultNewUserLdapAttributes()
    {
        $config = $this->config;
        $config['tlsMode'] = 'starttls';
        $config['passwordLdapHashAlgo'] = 'AD';
        $ldap = new LdapClientForTests($config);
        $attributes = $ldap->getParameter('newUserLdapAttributes');
        $this->assertEquals('user', $attributes['objectClass']);
        $this->assertEquals('%%LOGIN%%', $attributes['sAMAccountName']);
        $this->assertEquals('514', $attributes['userAccountControl']);
        $this->assertArrayNotHasKey('userPassword', $attributes);
    }

    function testEncodeActiveDirectoryPassword()
    {
        $config = $this->config;
        $config['tlsMode'] = 'starttls';
        $config['passwordLdapHashAlgo'] = 'AD';
        $ldap = new LdapClientForTests($config);

        $this->assertEquals("\"\0p\0a\0s\0s\0\"\0", $ldap->testEncodeActiveDirectoryPassword('pass'));
        $this->assertEquals("\"\0\xE9\0\xAC\x20\"\0", $ldap->testEncodeActiveDirectoryPassword('é€'));

        $this->expectException(\Jelix\Ldap\Exception::class);
        $ldap->testEncodeActiveDirectoryPassword("pass\xE9");
    }

    function testLogEscapesControlCharacters()
    {
        $logger = new ArrayLogger();
        $ldap = new LdapClientForTests($this->config, $logger);
        $ldap->testLog(5, "ldap user \"john\nLDAP error: fake\" not found");
        $this->assertEquals(array(array('error', 'ldap user "john\nLDAP error: fake" not found')), $logger->messages);
        $this->assertStringNotContainsString("\n", $logger->messages[0][1]);
    }

    function testUpdatableAttributes()
    {
        $config = $this->config;
        $config['searchAttributes'] = 'uid:login,displayName:realname,mail:email,userPassword:,objectClass:';
        $ldap = new LdapClientForTests($config);
        $ldap->testcheckUpdatableAttributes(array('mail' => 'a@b.c', 'DISPLAYNAME' => 'foo'));

        foreach (array('userPassword', 'USERPASSWORD', 'objectClass', 'unicodePwd', 'description') as $attr) {
            try {
                $ldap->testcheckUpdatableAttributes(array('mail' => 'a@b.c', $attr => 'foo'));
                $this->fail('attribute '.$attr.' should not be updatable');
            } catch (\Jelix\Ldap\Exception $e) {
                $this->assertStringContainsString($attr, $e->getMessage());
            }
        }
    }
}
