<?php
/**
 * @author      laurent Jouanneau
 * @copyright   2026 laurent Jouanneau
 * @link        https://www.jelix.org
 * @licence     MIT
 */
use Jelix\Ldap\LdapMigration;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests migration of configurations. No ldap server is needed.
 */
class ldapMigration_Test extends TestCase
{
    public static function getBindUserDNData()
    {
        return array(
            'attribute' => array('$dn', 'uid:login,mail:email', 'dn'),
            'other attribute' => array('$ldapattr', 'uid:login,mail:email', 'ldapattr'),
            'attribute has priority' => array(
                array('uid=%?%,ou=users,dc=XY,dc=fr', '%%LOGIN%%', '$ldapattr', 'cn=%%LOGIN%%,dc=XY,dc=fr'),
                'uid:login,mail:email',
                'ldapattr'
            ),
            'login mapped attribute' => array('%%LOGIN%%', 'uid:login,mail:email', 'uid'),
            'login mapped attribute, array' => array(
                array('cn=%?%,ou=users,dc=XY,dc=fr', '%%LOGIN%%'),
                'mail:email, sAMAccountName : login',
                'sAMAccountName'
            ),
            'login without mapping, dn' => array('%%LOGIN%%', 'dn:,mail:email', 'dn'),
            'login without mapping' => array('%%LOGIN%%', 'mail:email', 'dn'),
            'template with attribute' => array('uid=%?%,ou=users,dc=XY,dc=fr', 'uid:login,mail:email', 'dn'),
            'template with login' => array('cn=%%LOGIN%%,ou=users,dc=XY,dc=fr', 'uid:login,mail:email', 'dn'),
            'templates' => array(
                array('uid=%?%,ou=users,dc=XY,dc=fr', 'cn=%%LOGIN%%,ou=users,dc=XY,dc=fr'),
                '',
                'dn'
            ),
        );
    }

    #[DataProvider('getBindUserDNData')]
    public function testBindUserDNMigration($bindUserDN, $searchAttributes, $expectedBindAttribute)
    {
        $config = array(
            'hostname' => 'ldap.jelix',
            'searchUserBaseDN' => 'ou=people,dc=tests,dc=jelix',
            'searchUserFilter' => '(&(objectClass=inetOrgPerson)(uid=%%LOGIN%%))',
            'searchAttributes' => $searchAttributes,
            'bindUserDN' => $bindUserDN,
        );

        $newConfig = LdapMigration::migrateMultiauthConfiguration($config);

        $this->assertArrayNotHasKey('bindUserDN', $newConfig);
        $this->assertEquals($expectedBindAttribute, $newConfig['bindAttribute']);
    }

    public function testFeaturesMigration()
    {
        $config = array(
            'hostname' => 'ldap.jelix',
            'port' => 389,
            'searchUserBaseDN' => 'ou=people,dc=tests,dc=jelix',
            'searchUserFilter' => array(
                '(&(objectClass=inetOrgPerson)(uid=%%LOGIN%%))',
                '(&(objectClass=simpleSecurityObject)(cn=%%LOGIN%%))',
            ),
            'searchAttributes' => 'uid:login,mail:email',
            'bindUserDN' => 'uid=%?%,ou=people,dc=tests,dc=jelix',
            'featureCreateUser' => true,
            'featureUpdateUser' => true,
            'featureDeleteUser' => true,
        );

        $newConfig = LdapMigration::migrateLdapDaoConfiguration($config);

        $this->assertEquals(array(
            'hostname' => 'ldap.jelix',
            'port' => 389,
            'searchUserBaseDN' => 'ou=people,dc=tests,dc=jelix',
            'searchUserFilter' => array(
                '(&(objectClass=inetOrgPerson)(uid=%%LOGIN%%))',
                '(&(objectClass=simpleSecurityObject)(cn=%%LOGIN%%))',
            ),
            'searchAttributes' => 'uid:login,mail:email',
            'bindAttribute' => 'dn',
            'featureCreateUser' => false,
            'featureUpdateUser' => false,
            'featureDeleteUser' => false,
            'featureGroupLoad' => false,
        ), $newConfig);
    }

    public static function getGroupData()
    {
        return array(
            'no group filter' => array(
                array('searchGroupFilter' => '', 'searchGroupProperty' => 'cn', 'searchGroupBaseDN' => 'ou=groups,dc=tests,dc=jelix'),
                false,
                'ou=groups,dc=tests,dc=jelix',
            ),
            'no group property' => array(
                array('searchGroupFilter' => '(member=%%USERDN%%)', 'searchGroupProperty' => '', 'searchGroupBaseDN' => 'ou=groups,dc=tests,dc=jelix'),
                false,
                'ou=groups,dc=tests,dc=jelix',
            ),
            'all group parameters' => array(
                array('searchGroupFilter' => '(member=%%USERDN%%)', 'searchGroupProperty' => 'cn', 'searchGroupBaseDN' => 'ou=groups,dc=tests,dc=jelix'),
                true,
                'ou=groups,dc=tests,dc=jelix',
            ),
            'no group base DN' => array(
                array('searchGroupFilter' => '(member=%%USERDN%%)', 'searchGroupProperty' => 'cn', 'searchGroupBaseDN' => ''),
                true,
                'ou=people,dc=tests,dc=jelix',
            ),
            'no group base DN, several user base DN' => array(
                array('searchGroupFilter' => '(member=%%USERDN%%)', 'searchGroupProperty' => 'cn',
                    'searchUserBaseDN' => array('dc=tests,dc=jelix', 'ou=people,dc=tests,dc=jelix')),
                true,
                'dc=tests,dc=jelix',
            ),
        );
    }

    #[DataProvider('getGroupData')]
    public function testGroupMigration($groupConfig, $expectedFeature, $expectedBaseDN)
    {
        $config = array_merge(array(
            'hostname' => 'ldap.jelix',
            'searchUserBaseDN' => 'ou=people,dc=tests,dc=jelix',
            'searchUserFilter' => '(&(objectClass=inetOrgPerson)(uid=%%LOGIN%%))',
            'bindUserDN' => '$dn',
        ), $groupConfig);

        $newConfig = LdapMigration::migrateMultiauthConfiguration($config);

        $this->assertSame($expectedFeature, $newConfig['featureGroupLoad']);
        $this->assertEquals($expectedBaseDN, $newConfig['searchGroupBaseDN']);
    }
}
