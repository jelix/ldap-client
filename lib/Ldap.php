<?php
/**
 * @author     Laurent Jouanneau
 * @copyright  2019-2023 Laurent Jouanneau
 * @license   MIT
 */

namespace Jelix\Ldap;

use Psr\Log\LoggerInterface;

/**
 * it checks authentication into an ldap
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

    /**
     * Default user attributes list
     * @var array
     */
    protected $_default_attributes = array(
        "cn"=>"lastname",
        "name"=>"firstname"
    );

    protected $_defaultNewUserAttributes = array(
        "objectClass" => "inetOrgPerson",
        "userPassword" => "%%PASSWORD%%"
    );


    protected $uriConnect = '';

    protected $logger;

    /**
     * @param array $params configuration parameters
     */
    public function __construct($params, LoggerInterface $logger = null)
    {
        if (!extension_loaded('ldap')) {
            throw new Exception('PHP Ldap extension is not activated');
        }

        $this->logger = $logger;

        // default ldap parameters
        $_default_params = array(
            'hostname'      =>  'localhost',
            'tlsMode'       => '',
            'port'          =>  389,
            'adminUserDn'      =>  null,
            'adminPassword'      =>  null,
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
            'featureCreateUser' => true,
            'featureDeleteUser' => true,
            'featureChangePassword' => true,
        );

        $this->_params = $params;

        // iterate each default parameter and apply it to actual params if missing in $params.
        foreach ($_default_params as $name => $value) {
            if (!isset($this->_params[$name]) || $this->_params[$name] === '') {
                $this->_params[$name] = $value;
            }
        }

        if (!isset($this->_params['searchUserBaseDN']) || $this->_params['searchUserBaseDN'] == '') {
            throw new Exception('ldap configuration: base DN for search is missing');
        }

        if (!is_array($this->_params['searchUserBaseDN'])) {
            $this->_params['searchUserBaseDN'] = array($this->_params['searchUserBaseDN']);
        }

        if (!isset($this->_params['searchUserFilter']) || $this->_params['searchUserFilter'] == '') {
            throw new Exception('ldap configuration: search filter missing');
        }
        if (!is_array($this->_params['searchUserFilter'])) {
            $this->_params['searchUserFilter'] = array($this->_params['searchUserFilter']);
        }

        $cf = count($this->_params['searchUserFilter']);
        $cb = count($this->_params['searchUserBaseDN']);
        if ($cf != $cb) {
            if ($cf > 1 && $cb > 1) {
                throw new Exception('ldap configuration: wrong number of searchUserFilter and searchUserBaseDN values');
            }
            if ($cf === 1) {
                $this->_params['searchUserFilter'] = array_fill(0, $cb, $this->_params['searchUserFilter'][0]);
            }
            else if ($cb === 1) {
                $this->_params['searchUserBaseDN'] = array_fill(0, $cf, $this->_params['searchUserBaseDN'][0]);
            }
        }

        if (!isset($this->_params['searchAttributes']) || $this->_params['searchAttributes'] == '') {
            $this->_params['searchAttributes'] = $this->_default_attributes;
        } else {
            $attrs = explode(",", $this->_params['searchAttributes']);
            $this->_params['searchAttributes'] = array();
            foreach ($attrs as $attr) {
                if (strpos($attr, ':') === false) {
                    $attr = trim($attr);
                    $this->_params['searchAttributes'][$attr] = $attr;
                } else {
                    $attr = explode(':', $attr);
                    $this->_params['searchAttributes'][trim($attr[0])] = trim($attr[1]);
                }
            }
        }

        if (!isset($this->_params['newUserLdapAttributes']) || $this->_params['newUserLdapAttributes'] == '') {
            $this->_params['newUserLdapAttributes'] = $this->_defaultNewUserAttributes;
        } else {
            $attrs = explode(",", $this->_params['newUserLdapAttributes']);
            $this->_params['newUserLdapAttributes'] = array();
            foreach ($attrs as $attr) {
                if (strpos($attr, ':') !== false) {
                    $attr = explode(':', $attr);
                    $this->_params['newUserLdapAttributes'][trim($attr[0])] = trim($attr[1]);
                }
            }
        }

        if ($this->_params['newUserDN'] == '' && $this->_params['featureCreateUser']) {
            throw new Exception('ldap configuration: no newUserDN config parameter');
        }

        $uri = $this->_params['hostname'];

        if (preg_match('!^ldap(s?)://!', $uri, $m)) { // old way to specify ldaps protocol
            $predefinedPort = '';
            if (preg_match('!:(\d+)/?!', $uri, $mp)) {
                $predefinedPort = $mp[1];
            }
            if (isset($m[1]) && $m[1] == 's') {
                $this->_params['tlsMode'] = 'ldaps';
            }
            elseif ($this->_params['tlsMode'] == 'ldaps') {
                $this->_params['tlsMode'] = 'starttls';
            }
            if ($predefinedPort == '') {
                $uri .= ':'.$this->_params['port'];
            }
            else {
                $this->_params['port'] = $predefinedPort;
            }
            $this->uriConnect = $uri;
        }
        else {
            $uri .= ':'.$this->_params['port'];
            if ($this->_params['tlsMode'] == 'ldaps' || $this->_params['port'] == 636 ) {
                $this->uriConnect = 'ldaps://'.$uri;
                $this->_params['tlsMode'] = 'ldaps';
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
    public function getFeatures()
    {
        $feat = 0;
        if ($this->_params['featureChangePassword']) {
            $feat |= self::FEATURE_CHANGE_PASSWORD;
        }
        if ($this->_params['featureCreateUser']) {
            $feat |= self::FEATURE_CREATE_USER;
        }
        if ($this->_params['featureDeleteUser']) {
            $feat |= self::FEATURE_DELETE_USER;
        }
        return $feat;
    }

    /**
     * @param string $login
     * @return bool true if an account exists with this login
     */
    public function userExists($login)
    {
        $connectAdmin = $this->_bindLdapAdminUser();
        if (!$connectAdmin) {
            return false;
        }
        // see if the user exists into the ldap directory
        $result = $this->searchLdapUserAttributes($connectAdmin, $login);
        ldap_close($connectAdmin);
        return ($result !== false);
    }

    /**
     * @param string $login
     * @return UserLdapAttributes|null
     */
    public function getUser($login)
    {
        if (!$this->userExists($login)) {
            return null;
        }
        $connectAdmin = $this->_bindLdapAdminUser();
        if (!$connectAdmin) {
            return null;
        }
        // see if the user exists into the ldap directory
        $result = $this->searchLdapUserAttributes($connectAdmin, $login);
        //$this->searchUserGroups($connectAdmin, $userDn, $result, $login);
        ldap_close($connectAdmin);
        return $result;
    }

    /**
     * @param string $login
     * @param array $attributes list of attributes to change
     * @return void
     */
    public function updateUser($login, array $attributes)
    {
        if (!$this->userExists($login)) {
            return ;
        }
        $connectAdmin = $this->_bindLdapAdminUser();
        if (!$connectAdmin) {
            return ;
        }
        $ldapAttributes = $this->searchLdapUserAttributes($connectAdmin, $login);
        ldap_mod_replace($connectAdmin, $ldapAttributes->dn, $attributes);
        ldap_close($connectAdmin);
    }

    /**
     * @param string $login
     * @param string $password
     * @param string $email
     * @param string $name
     * @return bool true if it has been successfully created
     * @throws Exception
     */
    public function createUser($login, $password, $email, $name = '')
    {
        if (!$this->_params['featureCreateUser']) {
            return false;
        }

        $connectAdmin = $this->_bindLdapAdminUser();
        if (!$connectAdmin) {
            return false;
        }

        $ldapAttributes = $this->createLdapAttributes(array(
            'email' => $email,
            'realname' => $name ?: $login
        ));

        foreach($this->_params['newUserLdapAttributes'] as $attr=>$val) {
            if ($val[0] == '%') {
                $val = str_replace(array('%%PASSWORD%%', '%%LOGIN%%', '%%REALNAME%%'),
                    array($this->hashPassword($password), $login, $name ?: $login),
                    $val
                );
            }
            $ldapAttributes[$attr] = $val;
        }

        $dn = $this->createDn($this->_params['newUserDN'], $login, $ldapAttributes);
        $result = @ldap_add ($connectAdmin , $dn, $ldapAttributes);
        if (!$result) {
            //echo('ldap authentication: error when trying to create a user "'.$login.'": '.ldap_errno($connectAdmin).':'.ldap_error($connectAdmin));
            $this->logError('ldap authentication: error when trying to create a user "'.$login.'": '.ldap_errno($connectAdmin).':'.ldap_error($connectAdmin));
        }
        ldap_close($connectAdmin);
        return $result;
    }

    /**
     * Delete a user from the ldap
     *
     * @return UserLdapAttributes|bool
     *    the ldap attributes of the deleted user
     *    or true if the user is already deleted from the ldap
     *    or false if there is an issue
     */
    public function deleteUser($login)
    {
        if (!$this->_params['featureDeleteUser']) {
            return false;
        }
        $connectAdmin = $this->_bindLdapAdminUser();
        if (!$connectAdmin) {
            return false;
        }

        // see if the user exists into the ldap directory
        $attributes = $this->searchLdapUserAttributes($connectAdmin, $login);
        if ($attributes === false) {
            ldap_close($connectAdmin);
            return true;
        }
        //$this->searchUserGroups($connectAdmin, $userDn, $attributes, $login);
        $result = ldap_delete($connectAdmin, $attributes->dn);
        ldap_close($connectAdmin);

        if (!$result) {
            return false;
        }
        return $attributes;
    }

    /**
     * @param string $login
     * @param string $newpassword
     * @return bool true if the password has been changed
     * @throws Exception
     */
    public function changePassword($login, $newpassword)
    {
        if (!$this->_params['featureChangePassword']) {
            return false;
        }

        $connectAdmin = $this->_bindLdapAdminUser();
        if (!$connectAdmin) {
            return false;
        }

        // see if the user exists into the ldap directory
        $attributes = $this->searchLdapUserAttributes($connectAdmin, $login);
        if ($attributes === false) {
            ldap_close($connectAdmin);
            return false;
        }

        $entry = array(
            "userPassword" => $this->hashPassword($newpassword)
        );

        if (ldap_modify($connectAdmin, $attributes->dn, $entry) === false) {
            $this->logError('ldap error when trying to change password of user "'.$login.'": '.ldap_errno($connectAdmin).':'.ldap_error($connectAdmin));
            ldap_close($connectAdmin);
            return false;
        }
        return true;
    }


    /**
     * @param string $login
     * @param string $password
     * @return false|UserLdapAttributes
     */
    public function verifyAuthentication($login, $password)
    {
        if (trim($password) == '' || trim($login) == '') {
            // we don't want Unauthenticated Authentication
            // and Anonymous Authentication
            // https://tools.ietf.org/html/rfc4513#section-5.1
            return false;
        }

        $connectAdmin = $this->_bindLdapAdminUser();
        if (!$connectAdmin) {
            return false;
        }

        // see if the user exists into the ldap directory
        $attributes = $this->searchLdapUserAttributes($connectAdmin, $login);
        if ($attributes === false) {
            $this->logError('ldap authentication: user '.$login.' not found into the ldap');
            ldap_close($connectAdmin);
            return false;
        }

        $connect = $this->_getLinkId();
        if (!$connect) {
            $this->logError('ldap authentication: impossible to connect to ldap');
            ldap_close($connectAdmin);
            return false;
        }
        // authenticate user. let's try with all configured DN
        if ($this->_params['bindAttribute'] == 'dn') {
            $bindDn = $attributes->dn;
        }
        else {
            $bindDn = $attributes->ldapAttributes[$this->_params['bindAttribute']];
        }
        $bind = @ldap_bind($connect, $bindDn, $password);
        if (!$bind) {
            $this->logError('ldap authentication: cannot authenticate to ldap with given base DN for the login ' . $login. '. Wrong DN or password');
            $this->logLdapError($connect, 'tried to connect with "'.$attributes->dn.'"');;
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
     * @return UserLdapAttributes|false   ldap & user attributes or false if not found
     */
    protected function searchLdapUserAttributes($connect, $login)
    {
        $searchAttributes = array_keys($this->_params['searchAttributes']);
        if ($this->_params['bindAttribute'] != 'dn' && !isset($searchAttributes[$this->_params['bindAttribute']])) {
            $searchAttributes[] = $this->_params['bindAttribute'];
        }
        foreach ($this->_params['searchUserBaseDN'] as $k => $baseDn) {
            $filter = str_replace(
                array('%%LOGIN%%', '%%USERNAME%%'), // USERNAME deprecated
                $login,
                $this->_params['searchUserFilter'][$k]
            );
            $search = @ldap_search(
                $connect,
                $baseDn,
                $filter,
                $searchAttributes
            );
            if (!$search) {
                $this->logLdapError($connect, 'ldap: user "'.$login.'" not found with the DN "'.$baseDn.'" and filter "'.$filter.'"');
            }
            else if (($entry = @ldap_first_entry($connect, $search))) {
                $dn = ldap_get_dn($connect, $entry);
                $attributes = ldap_get_attributes($connect, $entry);
                return $this->readLdapAttributes($dn, $attributes);
            }
        }
        $this->logError('ldap user "'.$login.'" not found');
        return false;
    }

    /**
     * @param string $dnPattern
     * @param string $login
     * @param array $userLdapAttributes
     * @return false|string
     */
    protected function createDn($dnPattern, $login, array $userLdapAttributes)
    {
        if (preg_match('/^\\$\w+$/', trim($dnPattern))) {
            $dnAttribute = substr($dnPattern, 1);
            if (isset($userLdapAttributes[$dnAttribute])) {
                $realDn = $userLdapAttributes[$dnAttribute];
            } else {
                $this->logError('ldap authentication, bindUser notice: attribute '.$dnAttribute.' not found into user attributes');
                return false;
            }
        } elseif (preg_match_all('/(\w+)=%\?%/', $dnPattern, $m)) {
            $realDn = $dnPattern;
            foreach ($m[1] as $k => $attr) {
                if (isset($userLdapAttributes[$attr])) {
                    $realDn = str_replace($m[0][$k], $attr.'='.$userLdapAttributes[$attr], $realDn);
                } else {
                    $this->logError('ldap authentication, bindUser notice: attribute '.$attr.' not found into user attributes');
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
    protected function readLdapAttributes($dn, $origLdapAttributes)
    {
        $mapping = $this->_params['searchAttributes'];
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
    protected function createLdapAttributes($values)
    {
        $ldapAttributes = array();
        foreach($this->_params['searchAttributes'] as $ldapAttr => $attr) {
            if (isset($values[$attr])) {
                $ldapAttributes[$ldapAttr] = $values[$attr];
            }
        }
        return $ldapAttributes;
    }

    /**
     * Fill the UserLdapAttributes groups properties with the ldap groups of the user
     * @param $connect
     * @param UserLdapAttributes $userLdapAttributes
     * @param string $login
     * @return bool true if groups have been found
     */
    protected function searchUserGroups($connect, $userLdapAttributes, $login)
    {
        // Do not search for groups if no group filter passed
        if ($this->_params['searchGroupFilter'] == '') {
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
            $this->_params['searchGroupFilter']
        );
        $grpProp = $this->_params['searchGroupProperty'];

        $search = ldap_search(
            $connect,
            $this->_params['searchGroupBaseDN'],
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
                $this->logError('ldap authentication: no groups found for the user  "'.$login.'", with the searchGroupFilter query "'.$filter.'"');
            }
        }
        else {
            $this->logLdapError($connect, 'ldap error during group search for "'.$login.'", with the searchGroupFilter query "'.$filter.'"');
        }
        return false;
    }

    /**
     * open the connection to the ldap server
     */
    protected function _getLinkId()
    {
        if ($connect = @ldap_connect($this->uriConnect)) {
            //ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
            ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, $this->_params['protocolVersion']);
            ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);

            if ($this->_params['tlsMode'] == 'starttls') {
                if (!@ldap_start_tls($connect)) {
                    $this->logLdapError($connect, 'connection error: impossible to start TLS connection to '.$this->uriConnect);
                    return false;
                }
            }
            return $connect;
        }
        $this->logError('authloginpass: ldap error, bad syntax in the given uri "'.$this->uriConnect.'"');
        return false;
    }

    /**
     * open the connection to the ldap server
     * and bind to the admin user
     * @return resource|false the ldap connection
     */
    protected function _bindLdapAdminUser()
    {
        $connect = $this->_getLinkId();
        if (!$connect) {
            $this->logError('ldap authentication: impossible to connect to ldap');
            return false;
        }

        if ($this->_params['adminUserDn'] == '') {
            $bind = @ldap_bind($connect);
        } else {
            $bind = @ldap_bind($connect, $this->_params['adminUserDn'], $this->_params['adminPassword']);
        }
        if (!$bind) {
            if ($this->_params['adminUserDn'] == '') {
                $this->logError('ldap authentication: impossible to authenticate to ldap as anonymous admin user');
            } else {
                $this->logError('ldap authentication: impossible to authenticate to ldap with admin user '.$this->_params['adminUserDn']);
            }
            ldap_close($connect);
            return false;
        }
        return $connect;
    }


    protected function hashPassword($password)
    {
        switch($this->_params['passwordLdapHashAlgo']) {
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
                throw new Exception("ldap hash password: Unknown algorithm '".$this->_params['passwordLdapHashAlgo']."'");
        }
    }

    protected function generateSalt() {
        $generator = (new \RandomLib\Factory)->getMediumStrengthGenerator();
        $length = $this->_params['passwordLdapSaltLength'];
        $salt = $generator->generateString($length, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
        return $salt;
    }

    protected function getLdapError($connect, $contextMessage)
    {
        $message = "ldapdao error: $contextMessage \n";
        $message .= "\tldap error " . ldap_errno($connect) . ':' . ldap_error($connect);
        if (@ldap_get_option($connect, LDAP_OPT_DIAGNOSTIC_MESSAGE, $diagnostic)) {
            $message .= "\n\t" . $diagnostic;
        }
        return $message;
    }

    protected function log($message)
    {
        if ($this->logger) {
            $this->logger->info($message);
        }
    }

    protected function logError($message)
    {
        if ($this->logger) {
            $this->logger->error($message);
        }
    }

    protected function logLdapError($connect, $contextMessage)
    {
        $this->logError($this->getLdapError($connect, $contextMessage));
    }

}

