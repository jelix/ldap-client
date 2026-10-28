<?php
/**
 * @author     Laurent Jouanneau
 * @copyright  2019-2026 Laurent Jouanneau
 * @license   MIT
 */

namespace Jelix\Ldap;

use LDAP\Connection;
use LDAP\ResultEntry;
use Psr\Log\LoggerInterface;
use RandomLib\Factory;

/**
 * Helper class to do authentication against an ldap
 *
 * @internal see https://tools.ietf.org/html/rfc4510
 */
class Ldap
{
    /** @var int the library does not implement specific features */
    const FEATURE_NONE = 0;

    /** @var int password of a user can be changed */
    const FEATURE_CHANGE_PASSWORD = 1;

    /** @var int the library manage the user creation */
    const FEATURE_CREATE_USER = 2;

    /** @var int the library can delete user */
    const FEATURE_DELETE_USER = 4;

    /** @var int the library can update user */
    const FEATURE_UPDATE_USER = 8;

    protected const LOG_ERROR = 5;
    protected const LOG_WARNING = 4;
    protected const LOG_NOTICE = 3;
    protected const LOG_INFO = 2;
    protected const LOG_DEBUG = 1;

    protected static $loggerMethods = array(
        1 => 'debug',
        2 => 'info',
        3 => 'notice',
        4 => 'warning',
        5 => 'error'

    );

    /**
     * Default user attributes list
     * @var array
     */
    protected static $defaultAttributes = array(
        "cn"=>"lastname",
        "name"=>"firstname"
    );

    protected static $defaultNewUserAttributes = array(
        "objectClass" => "inetOrgPerson",
        "userPassword" => "%%PASSWORD%%"
    );

    protected static $defaultParameters = array(
        'hostname'      =>  'localhost',
        'tlsMode'       => '', // TLS mode: none, starttls, ldaps
        'port'          =>  389, // Port number
        'adminUserDn'      =>  null, // Admin user DN
        'adminPassword'      =>  null, // Admin user password
        'protocolVersion'   =>  3,
        'searchUserBaseDN' => '',
        'searchUserFilter' => '',
        'searchAttributes' => '',
        'bindAttribute' => 'dn',
        'searchGroupFilter' => '',
        'searchGroupProperty' => '',
        'searchGroupBaseDN' => '',
        'newUserDN' => '',
        'passwordLdapHashAlgo' => '',
        'passwordLdapSaltLength' => 5,
        'featureCreateUser' => false,
        'featureUpdateUser' => false,
        'featureDeleteUser' => false,
        'featureChangePassword' => false,
        'clientTLSCACertificateFile'=> '',
        'clientTLSCertificateFile'=> '',
        'clientTLSKeyFile'=> '',
    );

    protected $uriConnect = '';

    /** @var LoggerInterface|null  */
    protected $logger;

    /**
     * @var array list of configuration parameters
     */
    protected $parameters = array();

    /**
     * @param array $params configuration parameters
     */
    public function __construct(array $params, LoggerInterface $logger = null)
    {
        if (!extension_loaded('ldap')) {
            throw new Exception('PHP Ldap extension is not activated');
        }

        $this->logger = $logger;

        // default ldap parameters
        $this->parameters = $params;

        // iterate each default parameter and apply it to actual params if missing in $params.
        foreach (self::$defaultParameters as $name => $value) {
            if (!isset($this->parameters[$name]) || $this->parameters[$name] === '') {
                $this->parameters[$name] = $value;
            }
        }

        if (!isset($this->parameters['searchUserBaseDN']) || $this->parameters['searchUserBaseDN'] == '') {
            throw new Exception('ldap configuration: base DN for search is missing');
        }

        if (!is_array($this->parameters['searchUserBaseDN'])) {
            $this->parameters['searchUserBaseDN'] = array($this->parameters['searchUserBaseDN']);
        }

        if (!isset($this->parameters['searchUserFilter']) || $this->parameters['searchUserFilter'] == '') {
            throw new Exception('ldap configuration: search filter missing');
        }
        if (!is_array($this->parameters['searchUserFilter'])) {
            $this->parameters['searchUserFilter'] = array($this->parameters['searchUserFilter']);
        }

        $cf = count($this->parameters['searchUserFilter']);
        $cb = count($this->parameters['searchUserBaseDN']);
        if ($cf != $cb) {
            if ($cf > 1 && $cb > 1) {
                throw new Exception('ldap configuration: wrong number of searchUserFilter and searchUserBaseDN values');
            }
            if ($cf === 1) {
                $this->parameters['searchUserFilter'] = array_fill(0, $cb, $this->parameters['searchUserFilter'][0]);
            }
            else if ($cb === 1) {
                $this->parameters['searchUserBaseDN'] = array_fill(0, $cf, $this->parameters['searchUserBaseDN'][0]);
            }
        }

        if (!isset($this->parameters['searchAttributes']) || $this->parameters['searchAttributes'] == '') {
            $this->parameters['searchAttributes'] = self::$defaultAttributes;
        } else if (is_string($this->parameters['searchAttributes'])) {
            $attrs = explode(",", $this->parameters['searchAttributes']);
            $this->parameters['searchAttributes'] = array();
            foreach ($attrs as $attr) {
                if (strpos($attr, ':') === false) {
                    $attr = trim($attr);
                    $this->parameters['searchAttributes'][$attr] = $attr;
                } else {
                    $attr = explode(':', $attr);
                    $this->parameters['searchAttributes'][trim($attr[0])] = trim($attr[1]);
                }
            }
        } else if (is_array($this->parameters['searchAttributes'])) {
            foreach($this->parameters['searchAttributes'] as $ldapAttr => $userField) {
                if ($userField == '=') {
                    $this->parameters['searchAttributes'][$ldapAttr] = $ldapAttr;
                }
            }
        }

        if (!isset($this->parameters['newUserLdapAttributes']) || $this->parameters['newUserLdapAttributes'] == '') {
            $this->parameters['newUserLdapAttributes'] = self::$defaultNewUserAttributes;
        } else {
            $attrs = explode(",", $this->parameters['newUserLdapAttributes']);
            $this->parameters['newUserLdapAttributes'] = array();
            foreach ($attrs as $attr) {
                if (strpos($attr, ':') !== false) {
                    $attr = explode(':', $attr);
                    $this->parameters['newUserLdapAttributes'][trim($attr[0])] = trim($attr[1]);
                }
            }
        }

        if ($this->parameters['newUserDN'] == '' && $this->parameters['featureCreateUser']) {
            throw new Exception('ldap configuration: no newUserDN config parameter');
        }

        $uri = $this->parameters['hostname'];

        if (preg_match('!^ldap(s?)://!', $uri, $m)) { // old way to specify ldaps protocol
            $predefinedPort = '';
            if (preg_match('!:(\d+)/?!', $uri, $mp)) {
                $predefinedPort = $mp[1];
            }
            if (isset($m[1]) && $m[1] == 's') {
                $this->parameters['tlsMode'] = 'ldaps';
            }
            elseif ($this->parameters['tlsMode'] == 'ldaps') {
                $this->parameters['tlsMode'] = 'starttls';
            }
            if ($predefinedPort == '') {
                $uri .= ':'.$this->parameters['port'];
            }
            else {
                $this->parameters['port'] = $predefinedPort;
            }
            $this->uriConnect = $uri;
        }
        else {
            $uri .= ':'.$this->parameters['port'];
            if ($this->parameters['tlsMode'] == 'ldaps' || $this->parameters['port'] == 636 ) {
                $this->uriConnect = 'ldaps://'.$uri;
                $this->parameters['tlsMode'] = 'ldaps';
            }
            else {
                $this->uriConnect = 'ldap://'.$uri;
            }
        }
    }

    /**
     * Indicates which features are activated into the library
     *
     * @return int a combination of FEATURE_* constants
     */
    public function getFeatures() : int
    {
        $feat = 0;
        if ($this->parameters['featureChangePassword']) {
            $feat |= self::FEATURE_CHANGE_PASSWORD;
        }
        if ($this->parameters['featureCreateUser']) {
            $feat |= self::FEATURE_CREATE_USER;
        }
        if ($this->parameters['featureDeleteUser']) {
            $feat |= self::FEATURE_DELETE_USER;
        }
        if ($this->parameters['featureUpdateUser']) {
            $feat |= self::FEATURE_UPDATE_USER;
        }
        return $feat;
    }

    /**
     * Check if an LDAP account exists with this login
     *
     * @param string $login
     * @return bool true if an account exists with this login
     * @throws Exception
     */
    public function userExists(string $login) : bool
    {
        $connectAdmin = $this->_bindLdapAdminUser();

        // see if the user exists into the ldap directory
        $ldapEntry = $this->searchLdapUser($connectAdmin, $login);
        ldap_close($connectAdmin);
        return ($ldapEntry !== false);
    }

    /**
     * Retrieve user attributes from the ldap directory
     *
     * @param string $login
     * @param bool $loadAlsoGroups
     * @return UserLdapAttributes|null  LDAP attributes of the user, or null if the user is not found
     * @throws Exception
     */
    public function getUser(string $login, bool $loadAlsoGroups = false) : ?UserLdapAttributes
    {
        $connectAdmin = $this->_bindLdapAdminUser();

        // see if the user exists into the ldap directory
        $userAttrs = $this->searchLdapUserAttributes($connectAdmin, $login);

        if ($userAttrs === false) {
            ldap_close($connectAdmin);
            return null;
        }

        if ($loadAlsoGroups) {
            $this->searchUserGroups($connectAdmin, $userAttrs, $login);
        }
        ldap_close($connectAdmin);
        return $userAttrs;
    }

    /**
     * Update user attributes into the ldap directory
     *
     * The flag featureUpdateUser should be set to true in the LDAP parameters
     *
     * @param string $login
     * @param array $attributes list of attributes to change
     * @return bool  true if the user has been updated, false if it is not found.
     * @throws Exception
     */
    public function updateUser(string $login, array $attributes): bool
    {
        if (!$this->parameters['featureUpdateUser']) {
            return false;
        }

        $connectAdmin = $this->_bindLdapAdminUser();

        $ldapEntry = $this->searchLdapUser($connectAdmin, $login);
        if ($ldapEntry === false) {
            ldap_close($connectAdmin);
            return false;
        }
        $dn = ldap_get_dn($connectAdmin, $ldapEntry);
        $result = ldap_mod_replace($connectAdmin, $dn, $attributes);
        if (!$result) {
            $msg = 'ldap: error when trying to update attributes for "'.$login.'"';
            $this->log(self::LOG_ERROR, $msg, $connectAdmin);
            ldap_close($connectAdmin);
            throw new Exception($msg);
        }
        ldap_close($connectAdmin);
        return true;
    }

    /**
     * Create a new user account in the LDAP directory
     *
     * The flag featureCreateUser should be set to true in the LDAP parameters
     *
     * @param string $login
     * @param string $password
     * @param string $email
     * @param string $name
     * @return bool true if it has been successfully created
     * @throws Exception
     */
    public function createUser(string $login, string $password, string $email, string $name = ''): bool
    {
        if (!$this->parameters['featureCreateUser']) {
            return false;
        }

        $connectAdmin = $this->_bindLdapAdminUser();

        $ldapAttributes = $this->createLdapAttributes(array(
            'email' => $email,
            'realname' => $name ?: $login
        ));

        foreach($this->parameters['newUserLdapAttributes'] as $attr=> $val) {
            if ($val[0] == '%') {
                $val = str_replace(array('%%PASSWORD%%', '%%LOGIN%%', '%%REALNAME%%'),
                    array($this->hashPassword($password), $login, $name ?: $login),
                    $val
                );
            }
            $ldapAttributes[$attr] = $val;
        }

        $dn = $this->createDn($this->parameters['newUserDN'], $login, $ldapAttributes);
        if ($dn === false) {
            $msg = 'ldap: failed to create DN for user "'.$login.'"';
            $this->log(self::LOG_ERROR, $msg);
            ldap_close($connectAdmin);
            throw new Exception($msg);
        }

        $result = @ldap_add ($connectAdmin , $dn, $ldapAttributes);
        if (!$result) {
            $msg = 'ldap: error when trying to create a user "'.$login.'"';
            $this->log(self::LOG_ERROR, $msg, $connectAdmin);
            ldap_close($connectAdmin);
            throw new Exception($msg);
        }
        ldap_close($connectAdmin);
        return true;
    }

    /**
     * Delete a user from the ldap
     *
     * The flag featureDeleteUser should be set to true in the LDAP parameters
     *
     * @return UserLdapAttributes|bool
     *    the ldap attributes of the deleted user
     *    or true if the user is already deleted from the ldap
     *    or false if there is an issue
     * @throws Exception
     */
    public function deleteUser($login): bool|UserLdapAttributes
    {
        if (!$this->parameters['featureDeleteUser']) {
            return false;
        }
        $connectAdmin = $this->_bindLdapAdminUser();

        // see if the user exists into the ldap directory
        $attributes = $this->searchLdapUserAttributes($connectAdmin, $login);
        if ($attributes === false) {
            ldap_close($connectAdmin);
            return true;
        }

        $result = ldap_delete($connectAdmin, $attributes->dn);
        if (!$result) {
            $msg = 'ldap: error when trying to delete a user "'.$login.'"';
            $this->log(self::LOG_ERROR, $msg, $connectAdmin);
            ldap_close($connectAdmin);
            throw new Exception($msg);
        }
        ldap_close($connectAdmin);

        return $attributes;
    }

    /**
     * Delete a user from the ldap
     *
     * The flag featureChangePassword should be set to true in the LDAP parameters
     *
     * @param string $login
     * @param string $newPassword
     * @return bool true if the password has been changed
     * @throws Exception
     */
    public function changePassword(string $login, string $newPassword): bool
    {
        if (!$this->parameters['featureChangePassword']) {
            return false;
        }

        $connectAdmin = $this->_bindLdapAdminUser();

        // see if the user exists into the ldap directory
        $ldapEntry = $this->searchLdapUser($connectAdmin, $login);
        if ($ldapEntry === false) {
            ldap_close($connectAdmin);
            return false;
        }

        $dn = ldap_get_dn($connectAdmin, $ldapEntry);

        $entry = array(
            "userPassword" => $this->hashPassword($newPassword)
        );

        if (ldap_modify($connectAdmin, $dn, $entry) === false) {
            $msg = 'ldap: error when trying to change password of user "'.$login.'"';
            $this->log(self::LOG_ERROR, $msg, $connectAdmin);
            ldap_close($connectAdmin);
            throw new Exception($msg);
        }

        ldap_close($connectAdmin);
        return true;
    }

    /**
     * @param string $login
     * @param string $password
     * @return false|UserLdapAttributes
     * @throws Exception
     */
    public function verifyAuthentication(string $login, string $password): false|UserLdapAttributes
    {
        if (trim($password) == '' || trim($login) == '') {
            // we don't want Unauthenticated Authentication
            // and Anonymous Authentication
            // https://tools.ietf.org/html/rfc4513#section-5.1
            return false;
        }

        $connectAdmin = $this->_bindLdapAdminUser();

        // see if the user exists into the ldap directory
        $attributes = $this->searchLdapUserAttributes($connectAdmin, $login);
        if ($attributes === false) {
            $this->log(self::LOG_DEBUG, 'ldap authentication: user '.$login.' not found into the ldap');
            ldap_close($connectAdmin);
            return false;
        }

        // open a second connection to check the given login/password by doing a ldap_bind
        try {
            $connect = $this->_getLinkId();
        } catch(Exception $e) {
            ldap_close($connectAdmin);
            $this->log(self::LOG_ERROR, 'ldap authentication: impossible to connect to ldap to check password');
            throw $e;
        }

        // authenticate user. let's try with all configured DN
        if ($this->parameters['bindAttribute'] == 'dn') {
            $bindDn = $attributes->dn;
        }
        else {
            $bindDn = $attributes->ldapAttributes[$this->parameters['bindAttribute']];
        }
        $bind = @ldap_bind($connect, $bindDn, $password);
        if (!$bind) {
            $this->log(self::LOG_DEBUG, 'ldap authentication: cannot authenticate to ldap with given base DN for the login ' . $login. '. Wrong DN or password');
            $this->log(self::LOG_NOTICE, 'ldap authentication: failed to connect with "'.$attributes->dn.'"', $connect);
            ldap_close($connect);
            ldap_close($connectAdmin);
            return false;
        }
        ldap_close($connect);

        // retrieve the user group (if relevant)
        $this->searchUserGroups($connectAdmin, $attributes, $login);
        ldap_close($connectAdmin);

        return $attributes;
    }

    /**
     * Search an ldap user and returns his ldap attributes
     *
     * @return UserLdapAttributes|false   ldap user attributes or false if not found
     */
    protected function searchLdapUserAttributes(Connection $connect, string $login): false|UserLdapAttributes
    {
        $ldapEntry = $this->searchLdapUser($connect, $login);
        if (!$ldapEntry) {
            return false;
        }
        $dn = ldap_get_dn($connect, $ldapEntry);
        $attributes = ldap_get_attributes($connect, $ldapEntry);
        return $this->readLdapAttributes($dn, $attributes);
    }

    /**
     * Search an LDAP user
     *
     * @param Connection $connect
     * @param string $login
     * @return false|ResultEntry False if the user is not found, else the result entry
     */
    protected function searchLdapUser(Connection $connect, string $login): ResultEntry|false
    {
        $searchAttributes = array_keys($this->parameters['searchAttributes']);
        if ($this->parameters['bindAttribute'] != 'dn' && !isset($searchAttributes[$this->parameters['bindAttribute']])) {
            $searchAttributes[] = $this->parameters['bindAttribute'];
        }
        foreach ($this->parameters['searchUserBaseDN'] as $k => $baseDn) {
            $filter = str_replace(
                array('%%LOGIN%%', '%%USERNAME%%'), // USERNAME deprecated
                $login,
                $this->parameters['searchUserFilter'][$k]
            );
            $search = @ldap_search(
                $connect,
                $baseDn,
                $filter,
                $searchAttributes
            );
            if (!$search) {
                $this->log(self::LOG_DEBUG, 'ldap: user "'.$login.'" not found with the DN "'.$baseDn.'" and filter "'.$filter.'"', $connect);
            }
            else if (($entry = @ldap_first_entry($connect, $search))) {
                return $entry;
            }
        }
        $this->log(self::LOG_NOTICE, 'ldap user "'.$login.'" not found');
        return false;
    }

    /**
     * @param string $dnPattern
     * @param string $login
     * @param array $userLdapAttributes
     * @return false|string the dn of false if the DN cannot be created
     */
    protected function createDn(string $dnPattern, string $login, array $userLdapAttributes): false|string
    {
        if (preg_match('/^\\$\w+$/', trim($dnPattern))) {
            $dnAttribute = substr($dnPattern, 1);
            if (isset($userLdapAttributes[$dnAttribute])) {
                $realDn = $userLdapAttributes[$dnAttribute];
            } else {
                $this->log(self::LOG_ERROR, 'ldap: bindUser notice: attribute '.$dnAttribute.' not found into user attributes');
                return false;
            }
        } elseif (preg_match_all('/(\w+)=%\?%/', $dnPattern, $m)) {
            $realDn = $dnPattern;
            foreach ($m[1] as $k => $attr) {
                if (isset($userLdapAttributes[$attr])) {
                    $realDn = str_replace($m[0][$k], $attr.'='.$userLdapAttributes[$attr], $realDn);
                } else {
                    $this->log(self::LOG_ERROR, 'ldap: bindUser notice: attribute '.$attr.' not found into user attributes');
                    return false;
                }
            }
        } else {
            $realDn = str_replace(
                array('%%LOGIN%%', '%%USERNAME%%'), // USERNAME deprecated
                $login,
                $dnPattern
            );
        }
        return $realDn;
    }

    /**
     * Returns ldap attributes as an associative array, and build
     * a list of object attributes matching the mapping given into searchAttributes
     *
     * @param array $origLdapAttributes list of values provided by ldap_get_attributes
     * @return UserLdapAttributes
     */
    protected function readLdapAttributes(string $dn, array $origLdapAttributes): UserLdapAttributes
    {
        $mapping = $this->parameters['searchAttributes'];
        $attrs = new UserLdapAttributes();
        foreach ($origLdapAttributes as $ldapAttr => $attr) {
            if (isset($attr['count']) && $attr['count'] > 0) {
                if ($attr['count'] > 1) {
                    $val = array_shift($attr);
                } else {
                    $val = $attr[0];
                }
                $attrs->ldapAttributes[$ldapAttr] = $val;
                if (isset($mapping[$ldapAttr])) {
                    $objAttr = $mapping[$ldapAttr];
                    unset($mapping[$ldapAttr]);
                    if ($objAttr != '') {
                        $attrs->userAttributes[$objAttr] = $val;
                    }
                }
            }
        }

        foreach ($mapping as $ldapAttr => $objAttr) {
            if ($objAttr != '' && !isset($attrs->userAttributes[$objAttr])) {
                $attrs->userAttributes[$objAttr] = '';
            }
        }

        $attrs->dn = $dn;

        return $attrs;
    }

    /**
     * Construct a list of ldap attributes, corresponding to object attributes.
     *
     * It uses the searchAttributes configuration parameter.
     *
     * @param array $values list of object attributes
     * @return array list of ldap attributes
     */
    protected function createLdapAttributes(array $values): array
    {
        $ldapAttributes = array();
        foreach($this->parameters['searchAttributes'] as $ldapAttr => $attr) {
            if (isset($values[$attr])) {
                $ldapAttributes[$ldapAttr] = $values[$attr];
            }
        }
        return $ldapAttributes;
    }

    /**
     * Fill the UserLdapAttributes groups properties with the ldap groups of the user
     * @param Connection $connect
     * @param UserLdapAttributes $userLdapAttributes
     * @param string $login
     * @return bool true if groups have been found
     * @throws Exception
     */
    protected function searchUserGroups(Connection $connect, UserLdapAttributes $userLdapAttributes, string $login): bool
    {
        // Do not search for groups if no group filter passed
        if ($this->parameters['searchGroupFilter'] == '') {
            return false;
        }

        $searchStr = array_keys($userLdapAttributes->ldapAttributes);
        $searchStr[] = 'USERDN';
        $searchStr[] = 'LOGIN';
        $searchStr[] = 'USERNAME'; // USERNAME deprecated
        $searchStr = array_map(function ($val) {
            return '%%'.$val.'%%';
        }, $searchStr);
        $values = array_values($userLdapAttributes->ldapAttributes);
        // escape parenthesis
        $values = array_map(function ($val) {
            return str_replace(
                array('(', ')'),
                array('\\(', '\\)'),
                $val
            );
        }, $values);
        $values[] = $userLdapAttributes->dn;
        $values[] = $login;
        $values[] = $login;

        $filter = str_replace(
            $searchStr,
            $values,
            $this->parameters['searchGroupFilter']
        );
        $grpProp = $this->parameters['searchGroupProperty'];

        $search = ldap_search(
            $connect,
            $this->parameters['searchGroupBaseDN'],
            $filter,
            array($grpProp)
        );
        if ($search) {
            $entry = ldap_first_entry($connect, $search);
            if ($entry) {
                $userLdapAttributes->groups = array();
                do {
                    $attributes = ldap_get_attributes($connect, $entry);
                    if (isset($attributes[$grpProp]) && $attributes[$grpProp]['count'] > 0) {
                        $userLdapAttributes->groups[] = $attributes[$grpProp][0];
                    }
                } while ($entry = ldap_next_entry($connect, $entry));
                return true;
            }
            else {
                $this->log(self::LOG_DEBUG, 'ldap: no groups found for the user  "'.$login.'", with the searchGroupFilter query "'.$filter.'"');
            }
        }
        else {
            $msg = 'ldap error during group search for "'.$login.'", with the searchGroupFilter query "'.$filter.'"';
            $this->log(self::LOG_ERROR, $msg, $connect);
            ldap_close($connect);
            throw new Exception('ldap error during group search for "'.$login.'"');
        }
        return false;
    }

    /**
     * open the connection to the ldap server
     *
     * @throws Exception
     */
    protected function _getLinkId() : Connection
    {
        //ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);

        if ($connect = @ldap_connect($this->uriConnect)) {
            ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, $this->parameters['protocolVersion']);
            ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);

            if ($this->parameters['tlsMode'] != '') {
                if ($this->parameters['clientTLSCACertificateFile']) {
                    ldap_set_option(null, LDAP_OPT_X_TLS_CACERTFILE, $this->parameters['clientTLSCACertificateFile']);
                }
                if ($this->parameters['clientTLSCertificateFile']) {
                    ldap_set_option(null, LDAP_OPT_X_TLS_CERTFILE, $this->parameters['clientTLSCertificateFile']);
                }
                if ($this->parameters['clientTLSKeyFile']) {
                    ldap_set_option(null, LDAP_OPT_X_TLS_KEYFILE, $this->parameters['clientTLSKeyFile']);
                }

                ldap_set_option(null, LDAP_OPT_X_TLS_PROTOCOL_MIN , LDAP_OPT_X_TLS_PROTOCOL_TLS1_1);
                if (defined('LDAP_OPT_X_TLS_PROTOCOL_MAX') && defined('LDAP_OPT_X_TLS_PROTOCOL_TLS1_3')) {
                    ldap_set_option(null, LDAP_OPT_X_TLS_PROTOCOL_MAX , LDAP_OPT_X_TLS_PROTOCOL_TLS1_3);
                }
                // LDAP_OPT_X_TLS_NEWCTX (0x600f) - force libldap to rebuild
                // the TLS context from the options we just set
                // FIXME it doesn't work with PHP 8. perhaps in futur versions?
                //ldap_set_option(NULL, 0x600f, 0);
            }

            if ($this->parameters['tlsMode'] == 'starttls') {
                if (!@ldap_start_tls($connect)) {
                    $this->log(self::LOG_ERROR, 'ldap connection: impossible to start TLS connection to ' . $this->uriConnect, $connect);
                    throw new Exception('ldap connection: impossible to start TLS connection');
                }
            }

            return $connect;
        }
        $this->log(self::LOG_ERROR, 'ldap connection: impossible to connect to ldap with the given uri "'.$this->uriConnect.'"');
        throw new Exception('ldap connection: impossible to connect to ldap');
    }

    /**
     * open the connection to the ldap server
     * and bind to the admin user
     * @return Connection|false the ldap connection
     * @throws Exception
     */
    protected function _bindLdapAdminUser(): false|Connection
    {
        $connect = $this->_getLinkId();
        if ($this->parameters['adminUserDn'] == '') {
            $bind = @ldap_bind($connect);
        } else {
            $bind = @ldap_bind($connect, $this->parameters['adminUserDn'], $this->parameters['adminPassword']);
        }
        if (!$bind) {
            if ($this->parameters['adminUserDn'] == '') {
                $this->log(self::LOG_ERROR, 'ldap connection: impossible to authenticate to ldap as anonymous admin user');
            } else {
                $this->log(self::LOG_ERROR, 'ldap connection: impossible to authenticate to ldap with admin user '.$this->parameters['adminUserDn']);
            }
            ldap_close($connect);
            throw new Exception('ldap connection: impossible to authenticate to ldap with the main user');
        }
        return $connect;
    }

    /**
     * Hashes a password using the specified LDAP hashing algorithm.
     *
     * @param string $password The plaintext password to be hashed.
     * @return string The hashed password, formatted according to the specified algorithm.
     * @throws Exception If an unknown hashing algorithm is specified.
     */
    protected function hashPassword(string $password) : string
    {
        switch($this->parameters['passwordLdapHashAlgo']) {
            case 'SHA':
                return "{SHA}" . base64_encode(pack( "H*", sha1( $password )));
            case 'SSHA':
                $salt = $this->generateSalt();
                return "{SSHA}" . base64_encode(pack("H*", sha1($password . $salt)) . $salt);
            case 'MD5':
                return "{MD5}".base64_encode(pack( "H*", md5( $password )));
            case 'SMD5':
                $salt = $this->generateSalt();
                return "{SMD5}" . base64_encode(pack("H*", md5($password . $salt)) . $salt);
            case '':
                return $password;
            default:
                throw new Exception("ldap hash password: Unknown algorithm '".$this->parameters['passwordLdapHashAlgo']."'");
        }
    }

    /**
     * Generates a cryptographic salt string for password handling.
     *
     * @return string a randomly generated alphanumeric string of the specified length
     */
    protected function generateSalt() : string
    {
        $generator = (new Factory)->getMediumStrengthGenerator();
        $length = $this->parameters['passwordLdapSaltLength'];
        return $generator->generateString($length, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }

    /**
     * @param Connection $connect
     * @param string $contextMessage
     * @return string
     */
    protected function getLdapError(Connection $connect, string $contextMessage): string
    {
        $message = "ldapdao error: $contextMessage \n";
        $message .= "\tldap error " . ldap_errno($connect) . ':' . ldap_error($connect);
        if (@ldap_get_option($connect, LDAP_OPT_DIAGNOSTIC_MESSAGE, $diagnostic)) {
            $message .= "\n\t" . $diagnostic;
        }
        return $message;
    }

    /**
     * Logs a message of a specified type, optionally including LDAP error details.
     *
     * @param string $type The log type, used to determine the logger method.
     * @param string $message The message to be logged.
     * @param Connection|null $connect An optional connection object to retrieve LDAP error details.
     * @return void
     */
    protected function log(string $type, string $message, ?Connection $connect = null)
    {
        if (!$this->logger) {
            return;
        }
        if ($connect) {
            $message = $this->getLdapError($connect, $message);
        }

        $method = self::$loggerMethods[$type] ?? 'info';
        $this->logger->$method($message);
    }
}
