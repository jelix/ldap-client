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

    /** @var int the library retrieves groups of the user */
    const FEATURE_GROUP_LOAD = 16;

    protected const LOG_ERROR = 5;
    protected const LOG_WARNING = 4;
    protected const LOG_NOTICE = 3;
    protected const LOG_INFO = 2;
    protected const LOG_DEBUG = 1;

    /** @var int ldap error code returned when the base DN of a search does not exist */
    protected const LDAP_ERR_NO_SUCH_OBJECT = 32;

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
        "userPassword" => "%%PASSWORD%%",
        "cn" => "%%REALNAME%%",
        "sn" => "%%REALNAME%%",
    );

    /**
     * Default attributes of a new user, for Active Directory (passwordLdapHashAlgo=AD)
     *
     * The account is created disabled, and enabled after the password is set
     * @var array
     */
    protected static $defaultNewUserAttributesAD = array(
        "objectClass" => "user",
        "sAMAccountName" => "%%LOGIN%%",
        "cn" => "%%REALNAME%%",
        "displayName" => "%%REALNAME%%",
        "userAccountControl" => "514",
    );

    /** @var int flag of userAccountControl indicating a disabled account (Active Directory) */
    protected const AD_UAC_ACCOUNTDISABLE = 0x2;

    /** @var int flag of userAccountControl indicating that no password is required (Active Directory) */
    protected const AD_UAC_PASSWD_NOTREQD = 0x20;

    /** @var int userAccountControl value of a normal enabled account (Active Directory) */
    protected const AD_UAC_NORMAL_ACCOUNT = 0x200;

    /**
     * Ldap attributes that cannot be modified with updateUser()
     * (lower case names)
     * @var string[]
     */
    protected static $notUpdatableAttributes = array(
        'userpassword',
        'unicodepwd',
        'objectclass',
    );

    protected static $tlsModes = array('', 'starttls', 'ldaps');

    protected static $defaultParameters = array(
        'hostname'      =>  'localhost',
        'tlsMode'       => '', // TLS mode: '' (or 'none'), 'starttls', 'ldaps'
        'port'          =>  389, // Port number
        'adminUserDn'      =>  null, // Admin user DN
        'adminPassword'      =>  null, // Admin user password
        'protocolVersion'   =>  3,
        'networkTimeout' => 10, // timeout in seconds to connect to the server
        'timeLimit' => 10, // time limit in seconds for search operations
        'searchUserBaseDN' => '',
        'searchUserFilter' => '',
        'searchAttributes' => '',
        'bindAttribute' => 'dn',
        'searchGroupFilter' => '',
        'searchGroupProperty' => '',
        'searchGroupBaseDN' => '',
        'newUserDN' => '',
        'passwordLdapHashAlgo' => '',
        'passwordLdapSaltLength' => 8, // salt length in bytes
        'featureCreateUser' => false,
        'featureUpdateUser' => false,
        'featureDeleteUser' => false,
        'featureChangePassword' => false,
        'featureGroupLoad' => false,
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
    public function __construct(array $params, ?LoggerInterface $logger = null)
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

        $tlsMode = strtolower(trim((string)$this->parameters['tlsMode']));
        if ($tlsMode == 'none') {
            $tlsMode = '';
        }
        if (!in_array($tlsMode, self::$tlsModes, true)) {
            throw new Exception('ldap configuration: invalid tlsMode value "'.$this->parameters['tlsMode'].'". Possible values: "" (or "none"), "starttls", "ldaps"');
        }
        $this->parameters['tlsMode'] = $tlsMode;

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
                    if ($attr !== '') {
                        $this->parameters['searchAttributes'][$attr] = $attr;
                    }
                } else {
                    $attr = explode(':', $attr, 2);
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

        $newUserAttrs = $this->parameters['newUserLdapAttributes'] ?? '';
        if ($newUserAttrs === '' || $newUserAttrs === array() || $newUserAttrs === null) {
            $this->parameters['newUserLdapAttributes'] = $this->useActiveDirectoryPassword()
                ? self::$defaultNewUserAttributesAD
                : self::$defaultNewUserAttributes;
        } else if (is_string($newUserAttrs)) {
            $this->parameters['newUserLdapAttributes'] = array();
            foreach (explode(",", $newUserAttrs) as $attr) {
                if (strpos($attr, ':') === false) {
                    continue;
                }
                list($name, $value) = explode(':', $attr, 2);
                $name = trim($name);
                $value = trim($value);
                if (isset($this->parameters['newUserLdapAttributes'][$name])) {
                    // the same attribute given several times: it is a multi-valued attribute
                    $this->parameters['newUserLdapAttributes'][$name] = array_merge(
                        (array) $this->parameters['newUserLdapAttributes'][$name],
                        array($value)
                    );
                } else {
                    $this->parameters['newUserLdapAttributes'][$name] = $value;
                }
            }
        } else if (!is_array($newUserAttrs)) {
            throw new Exception('ldap configuration: newUserLdapAttributes should be a string or an array');
        }

        if ($this->parameters['newUserDN'] == '' && $this->parameters['featureCreateUser']) {
            throw new Exception('ldap configuration: no newUserDN config parameter');
        }

        if ($this->parameters['featureGroupLoad']) {
            foreach (array('searchGroupFilter', 'searchGroupProperty', 'searchGroupBaseDN') as $name) {
                if (trim((string) $this->parameters[$name]) === '') {
                    throw new Exception('ldap configuration: '.$name.' config parameter is missing, it is required when featureGroupLoad is enabled');
                }
            }
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

        if ($this->useActiveDirectoryPassword() && $this->parameters['tlsMode'] == '') {
            throw new Exception('ldap configuration: Active Directory refuses to set passwords on an unencrypted connection. tlsMode should be "starttls" or "ldaps" when passwordLdapHashAlgo is "AD"');
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
        if ($this->parameters['featureGroupLoad']) {
            $feat |= self::FEATURE_GROUP_LOAD;
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
        $login = trim($login, " ");
        $connectAdmin = $this->_bindLdapAdminUser();
        try {
            // see if the user exists into the ldap directory
            return ($this->searchLdapUser($connectAdmin, $login) !== false);
        } finally {
            ldap_close($connectAdmin);
        }
    }

    /**
     * Retrieve user attributes from the ldap directory
     *
     * @param string $login
     * @param bool $loadAlsoGroups true to retrieve also groups of the user. Groups
     *                              are retrieved only if featureGroupLoad is enabled.
     * @return UserLdapAttributes|null  LDAP attributes of the user, or null if the user is not found
     * @throws Exception
     */
    public function getUser(string $login, bool $loadAlsoGroups = false) : ?UserLdapAttributes
    {
        $login = trim($login, " ");
        $connectAdmin = $this->_bindLdapAdminUser();
        try {
            // see if the user exists into the ldap directory
            $userAttrs = $this->searchLdapUserAttributes($connectAdmin, $login);
            if ($userAttrs === false) {
                return null;
            }

            if ($loadAlsoGroups) {
                $this->searchUserGroups($connectAdmin, $userAttrs, $login);
            }
            return $userAttrs;
        } finally {
            ldap_close($connectAdmin);
        }
    }

    /**
     * Update user attributes into the ldap directory
     *
     * The flag featureUpdateUser should be set to true in the LDAP parameters.
     *
     * Only ldap attributes listed into the searchAttributes parameter
     * can be modified. Passwords and object classes cannot be modified.
     *
     * @param string $login
     * @param array $attributes list of ldap attributes to change
     * @return bool  true if the user has been updated, false if it is not found.
     * @throws Exception
     */
    public function updateUser(string $login, array $attributes): bool
    {
        if (!$this->parameters['featureUpdateUser']) {
            return false;
        }

        $login = trim($login, " ");

        $this->checkUpdatableAttributes($attributes);

        $connectAdmin = $this->_bindLdapAdminUser();
        try {
            $ldapEntry = $this->searchLdapUser($connectAdmin, $login);
            if ($ldapEntry === false) {
                return false;
            }
            if (count($attributes) == 0) {
                return true;
            }
            $dn = $this->getEntryDn($connectAdmin, $ldapEntry, $login);
            if (!@ldap_mod_replace($connectAdmin, $dn, $attributes)) {
                $msg = 'ldap: error when trying to update attributes for "'.$login.'"';
                $this->log(self::LOG_ERROR, $msg, $connectAdmin);
                throw new Exception($msg);
            }
            return true;
        } finally {
            ldap_close($connectAdmin);
        }
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

        if (!$this->isValidLogin($login)) {
            $msg = 'ldap: invalid login "'.$login.'" for the new user';
            $this->log(self::LOG_ERROR, $msg);
            throw new Exception($msg);
        }

        $realName = $name ?: $login;
        $useExop = $this->usePasswordModifyExtendedOperation();
        $useAD = $this->useActiveDirectoryPassword();

        $ldapAttributes = $this->createLdapAttributes(array(
            'email' => $email,
            'realname' => $realName
        ));

        $replacements = array(
            '%%LOGIN%%' => $login,
            '%%REALNAME%%' => $realName,
        );

        foreach($this->parameters['newUserLdapAttributes'] as $attr => $values) {
            $newValues = array();
            foreach ((array) $values as $val) {
                $val = (string) $val;
                if (strpos($val, '%%PASSWORD%%') !== false) {
                    if ($useExop || $useAD) {
                        // the password will be set after the creation
                        continue;
                    }
                    if (!isset($replacements['%%PASSWORD%%'])) {
                        $replacements['%%PASSWORD%%'] = $this->hashPassword($password);
                    }
                }
                $val = strtr($val, $replacements);
                if ($val !== '') {
                    $newValues[] = $val;
                }
            }
            if (count($newValues) == 1) {
                $ldapAttributes[$attr] = $newValues[0];
            }
            else if (count($newValues) > 1) {
                $ldapAttributes[$attr] = $newValues;
            }
        }

        $dn = $this->createDn($this->parameters['newUserDN'], $login, $ldapAttributes);
        if ($dn === false) {
            $msg = 'ldap: failed to create DN for user "'.$login.'"';
            $this->log(self::LOG_ERROR, $msg);
            throw new Exception($msg);
        }

        $connectAdmin = $this->_bindLdapAdminUser();
        try {
            if (!@ldap_add($connectAdmin, $dn, $ldapAttributes)) {
                $msg = 'ldap: error when trying to create a user "'.$login.'"';
                $this->log(self::LOG_ERROR, $msg, $connectAdmin);
                throw new Exception($msg);
            }

            if ($useExop && @ldap_exop_passwd($connectAdmin, $dn, '', $password) === false) {
                $msg = 'ldap: error when trying to set the password of the new user "'.$login.'"';
                $this->log(self::LOG_ERROR, $msg, $connectAdmin);
                // we don't want an account without password
                @ldap_delete($connectAdmin, $dn);
                throw new Exception($msg);
            }

            if ($useAD) {
                $this->setActiveDirectoryPasswordOfNewUser($connectAdmin, $dn, $login, $password, $ldapAttributes);
            }
            return true;
        } finally {
            ldap_close($connectAdmin);
        }
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
    public function deleteUser(string $login): bool|UserLdapAttributes
    {
        if (!$this->parameters['featureDeleteUser']) {
            return false;
        }

        $login = trim($login, " ");

        $connectAdmin = $this->_bindLdapAdminUser();
        try {
            // see if the user exists into the ldap directory
            $attributes = $this->searchLdapUserAttributes($connectAdmin, $login);
            if ($attributes === false) {
                return true;
            }

            if (!@ldap_delete($connectAdmin, $attributes->dn)) {
                $msg = 'ldap: error when trying to delete a user "'.$login.'"';
                $this->log(self::LOG_ERROR, $msg, $connectAdmin);
                throw new Exception($msg);
            }
            return $attributes;
        } finally {
            ldap_close($connectAdmin);
        }
    }

    /**
     * Change the password of a user
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

        $login = trim($login, " ");
        $connectAdmin = $this->_bindLdapAdminUser();
        try {
            // see if the user exists into the ldap directory
            $ldapEntry = $this->searchLdapUser($connectAdmin, $login);
            if ($ldapEntry === false) {
                return false;
            }

            $dn = $this->getEntryDn($connectAdmin, $ldapEntry, $login);

            if ($this->usePasswordModifyExtendedOperation()) {
                $result = @ldap_exop_passwd($connectAdmin, $dn, '', $newPassword);
            } else if ($this->useActiveDirectoryPassword()) {
                $result = @ldap_mod_replace($connectAdmin, $dn, array(
                    "unicodePwd" => $this->encodeActiveDirectoryPassword($newPassword)
                ));
            } else {
                $result = @ldap_modify($connectAdmin, $dn, array(
                    "userPassword" => $this->hashPassword($newPassword)
                ));
            }

            if ($result === false) {
                $msg = 'ldap: error when trying to change password of user "'.$login.'"';
                $this->log(self::LOG_ERROR, $msg, $connectAdmin);
                throw new Exception($msg);
            }
            return true;
        } finally {
            ldap_close($connectAdmin);
        }
    }

    /**
     * Verify the password of a user
     *
     * Note: the given login may differ from the login stored into the
     * directory (case, spaces...), as ldap comparisons are often case-insensitive.
     * Use the returned attributes to know the real login of the user.
     *
     * @param string $login
     * @param string $password
     * @return false|UserLdapAttributes
     * @throws Exception
     */
    public function verifyAuthentication(string $login, string $password): false|UserLdapAttributes
    {
        $login = trim($login, " ");
        if (trim($password) == '' || trim($login) == '') {
            // we don't want Unauthenticated Authentication
            // and Anonymous Authentication
            // https://tools.ietf.org/html/rfc4513#section-5.1
            return false;
        }

        $connectAdmin = $this->_bindLdapAdminUser();
        try {
            // see if the user exists into the ldap directory
            $attributes = $this->searchLdapUserAttributes($connectAdmin, $login);
            if ($attributes === false) {
                $this->log(self::LOG_DEBUG, 'ldap authentication: user '.$login.' not found into the ldap');
                return false;
            }

            if ($this->parameters['bindAttribute'] == 'dn') {
                $bindDn = $attributes->dn;
            }
            else {
                $bindDn = $this->getLdapAttributeValue($attributes, $this->parameters['bindAttribute']);
            }

            if (!is_string($bindDn) || trim($bindDn) === '') {
                // an empty DN would lead to an unauthenticated bind, that
                // some servers accept whatever the password.
                $this->log(self::LOG_ERROR, 'ldap authentication: no DN to bind for the login "'.$login.'". Attribute "'.$this->parameters['bindAttribute'].'" is missing or empty');
                return false;
            }

            // open a second connection to check the given login/password by doing a ldap_bind
            try {
                $connect = $this->_getLinkId();
            } catch(Exception $e) {
                $this->log(self::LOG_ERROR, 'ldap authentication: impossible to connect to ldap to check password');
                throw $e;
            }

            try {
                if (!@ldap_bind($connect, $bindDn, $password)) {
                    $this->log(self::LOG_DEBUG, 'ldap authentication: cannot authenticate to ldap with given base DN for the login ' . $login. '. Wrong DN or password');
                    $this->log(self::LOG_NOTICE, 'ldap authentication: failed to connect with "'.$bindDn.'"', $connect);
                    return false;
                }
            } finally {
                ldap_close($connect);
            }

            // retrieve the user groups (if featureGroupLoad is enabled)
            $this->searchUserGroups($connectAdmin, $attributes, $login);
            return $attributes;
        } finally {
            ldap_close($connectAdmin);
        }
        return false;
    }

    /**
     * Search an ldap user and returns his ldap attributes
     *
     * @return UserLdapAttributes|false   ldap user attributes or false if not found
     * @throws Exception
     */
    protected function searchLdapUserAttributes(Connection $connect, string $login): false|UserLdapAttributes
    {
        $ldapEntry = $this->searchLdapUser($connect, $login);
        if (!$ldapEntry) {
            return false;
        }
        $dn = $this->getEntryDn($connect, $ldapEntry, $login);
        $attributes = @ldap_get_attributes($connect, $ldapEntry);
        return $this->readLdapAttributes($dn, $attributes);
    }

    /**
     * Search an LDAP user
     *
     * @param Connection $connect
     * @param string $login
     * @return false|ResultEntry False if the user is not found, else the result entry
     * @throws Exception when the search fails, or when several users match the login
     */
    protected function searchLdapUser(Connection $connect, string $login): ResultEntry|false
    {
        if (!$this->isValidLogin($login)) {
            $this->log(self::LOG_NOTICE, 'ldap: invalid login "'.$login.'"');
            return false;
        }

        $searchAttributes = array_keys($this->parameters['searchAttributes']);
        $bindAttribute = $this->parameters['bindAttribute'];
        if ($bindAttribute != 'dn' && !in_array(strtolower($bindAttribute), array_map('strtolower', $searchAttributes), true)) {
            $searchAttributes[] = $bindAttribute;
        }

        $escapedLogin = ldap_escape($login, '', LDAP_ESCAPE_FILTER);

        foreach ($this->parameters['searchUserBaseDN'] as $k => $baseDn) {
            $filter = str_replace(
                array('%%LOGIN%%', '%%USERNAME%%'), // USERNAME deprecated
                $escapedLogin,
                $this->parameters['searchUserFilter'][$k]
            );
            // we ask 2 entries at most, to detect ambiguous results
            $search = @ldap_search(
                $connect,
                $baseDn,
                $filter,
                $searchAttributes,
                0,
                2
            );
            if ($search === false) {
                if (ldap_errno($connect) == self::LDAP_ERR_NO_SUCH_OBJECT) {
                    $this->log(self::LOG_DEBUG, 'ldap: the base DN "'.$baseDn.'" does not exist');
                    continue;
                }
                $msg = 'ldap: error during the search of the user "'.$login.'" with the base DN "'.$baseDn.'"';
                $this->log(self::LOG_ERROR, $msg.' and filter "'.$filter.'"', $connect);
                throw new Exception($msg);
            }

            $count = ldap_count_entries($connect, $search);
            if ($count > 1) {
                $msg = 'ldap: several entries match the login "'.$login.'" with the base DN "'.$baseDn.'"';
                $this->log(self::LOG_ERROR, $msg.' and filter "'.$filter.'"');
                throw new Exception($msg);
            }
            if ($count == 1) {
                return ldap_first_entry($connect, $search);
            }
            $this->log(self::LOG_DEBUG, 'ldap: user "'.$login.'" not found with the DN "'.$baseDn.'" and filter "'.$filter.'"');
        }
        $this->log(self::LOG_NOTICE, 'ldap user "'.$login.'" not found');
        return false;
    }

    /**
     * Check that the login does not contain characters we don't want
     *
     * Logins with spaces at the beginning or at the end are refused, as
     * many ldap servers ignore these spaces during comparison: the user could
     * be recognized with a login that is different from the one stored into the
     * directory.
     *
     * @param string $login
     * @return bool
     */
    protected function isValidLogin(string $login): bool
    {
        if ($login === '' || trim($login) !== $login) {
            return false;
        }
        // control characters (NUL, line feed...) are not allowed
        return !preg_match('/[\x00-\x1F\x7F]/', $login);
    }

    /**
     * @param Connection $connect
     * @param ResultEntry $entry
     * @param string $login
     * @return string
     * @throws Exception
     */
    protected function getEntryDn(Connection $connect, ResultEntry $entry, string $login): string
    {
        $dn = @ldap_get_dn($connect, $entry);
        if ($dn === false || $dn === '') {
            $msg = 'ldap: cannot retrieve the DN of the user "'.$login.'"';
            $this->log(self::LOG_ERROR, $msg, $connect);
            throw new Exception($msg);
        }
        return $dn;
    }

    /**
     * Verify that given ldap attributes can be modified by updateUser()
     *
     * @param array $attributes
     * @throws Exception
     */
    protected function checkUpdatableAttributes(array $attributes): void
    {
        $allowedAttributes = array_map('strtolower', array_keys($this->parameters['searchAttributes']));
        foreach ($attributes as $name => $value) {
            $lowerName = strtolower((string)$name);
            if (in_array($lowerName, self::$notUpdatableAttributes, true)
                || !in_array($lowerName, $allowedAttributes, true)
            ) {
                $msg = 'ldap: the attribute "'.$name.'" cannot be modified';
                $this->log(self::LOG_ERROR, $msg);
                throw new Exception($msg);
            }
        }
    }

    /**
     * @param string $dnPattern
     * @param string $login
     * @param array $userLdapAttributes
     * @return false|string the dn of false if the DN cannot be created
     */
    protected function createDn(string $dnPattern, string $login, array $userLdapAttributes): false|string
    {
        if (preg_match('/^\\$(\w+)$/', trim($dnPattern), $m)) {
            // the DN is the value of an attribute. This value should be a valid DN.
            $dnAttribute = $m[1];
            if (isset($userLdapAttributes[$dnAttribute])) {
                $realDn = $userLdapAttributes[$dnAttribute];
                if (is_array($realDn)) {
                    $realDn = reset($realDn);
                }
            } else {
                $this->log(self::LOG_ERROR, 'ldap: bindUser notice: attribute '.$dnAttribute.' not found into user attributes');
                return false;
            }
        } elseif (preg_match_all('/(\w+)=%\?%/', $dnPattern, $m)) {
            $realDn = $dnPattern;
            foreach ($m[1] as $k => $attr) {
                if (isset($userLdapAttributes[$attr])) {
                    $value = $userLdapAttributes[$attr];
                    if (is_array($value)) {
                        $value = reset($value);
                    }
                    $realDn = str_replace($m[0][$k], $attr.'='.ldap_escape((string)$value, '', LDAP_ESCAPE_DN), $realDn);
                } else {
                    $this->log(self::LOG_ERROR, 'ldap: bindUser notice: attribute '.$attr.' not found into user attributes');
                    return false;
                }
            }
        } else {
            $realDn = str_replace(
                array('%%LOGIN%%', '%%USERNAME%%'), // USERNAME deprecated
                ldap_escape($login, '', LDAP_ESCAPE_DN),
                $dnPattern
            );
        }
        return $realDn;
    }

    /**
     * Returns ldap attributes as an associative array, and build
     * a list of object attributes matching the mapping given into searchAttributes
     *
     * Names of ldap attributes are case-insensitive. Names given into the
     * searchAttributes configuration parameter are used as keys.
     *
     * @param array $origLdapAttributes list of values provided by ldap_get_attributes
     * @return UserLdapAttributes
     */
    protected function readLdapAttributes(string $dn, array $origLdapAttributes): UserLdapAttributes
    {
        $mapping = array();
        foreach ($this->parameters['searchAttributes'] as $ldapAttr => $objAttr) {
            $mapping[strtolower($ldapAttr)] = array($ldapAttr, $objAttr);
        }

        $attrs = new UserLdapAttributes();
        foreach ($origLdapAttributes as $ldapAttr => $attr) {
            if (!is_array($attr) || !isset($attr['count']) || $attr['count'] == 0) {
                continue;
            }
            unset($attr['count']);
            $values = array_values($attr);
            $lowerAttr = strtolower($ldapAttr);
            if (isset($mapping[$lowerAttr])) {
                list($ldapAttr, $objAttr) = $mapping[$lowerAttr];
                unset($mapping[$lowerAttr]);
                if ($objAttr != '') {
                    $attrs->userAttributes[$objAttr] = $values[0];
                }
            }
            $attrs->ldapAttributes[$ldapAttr] = $values[0];
            $attrs->ldapAttributesValues[$ldapAttr] = $values;
        }

        foreach ($mapping as list($ldapAttr, $objAttr)) {
            if ($objAttr != '' && !isset($attrs->userAttributes[$objAttr])) {
                $attrs->userAttributes[$objAttr] = '';
            }
        }

        $attrs->dn = $dn;

        return $attrs;
    }

    /**
     * Returns the value of an ldap attribute, whatever the case of its name
     *
     * @param UserLdapAttributes $attributes
     * @param string $name
     * @return string|null null if the attribute does not exist
     */
    protected function getLdapAttributeValue(UserLdapAttributes $attributes, string $name): ?string
    {
        foreach ($attributes->ldapAttributes as $ldapAttr => $value) {
            if (strcasecmp($ldapAttr, $name) === 0) {
                return $value;
            }
        }
        return null;
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
        if (!$this->parameters['featureGroupLoad']) {
            return false;
        }

        // all values inserted into the filter should be escaped
        $replacements = array();
        foreach ($userLdapAttributes->ldapAttributes as $ldapAttr => $value) {
            $replacements['%%'.$ldapAttr.'%%'] = ldap_escape((string)$value, '', LDAP_ESCAPE_FILTER);
        }
        $replacements['%%USERDN%%'] = ldap_escape($userLdapAttributes->dn, '', LDAP_ESCAPE_FILTER);
        $replacements['%%LOGIN%%'] = ldap_escape($login, '', LDAP_ESCAPE_FILTER);
        $replacements['%%USERNAME%%'] = $replacements['%%LOGIN%%']; // USERNAME deprecated

        // strtr does replacements in one pass: a value containing a placeholder is not modified
        $filter = strtr($this->parameters['searchGroupFilter'], $replacements);
        $grpProp = $this->parameters['searchGroupProperty'];

        $search = @ldap_search(
            $connect,
            $this->parameters['searchGroupBaseDN'],
            $filter,
            array($grpProp)
        );
        if ($search === false) {
            $msg = 'ldap error during group search for "'.$login.'", with the searchGroupFilter query "'.$filter.'"';
            $this->log(self::LOG_ERROR, $msg, $connect);
            throw new Exception('ldap error during group search for "'.$login.'"');
        }

        $entry = @ldap_first_entry($connect, $search);
        if (!$entry) {
            $this->log(self::LOG_DEBUG, 'ldap: no groups found for the user  "'.$login.'", with the searchGroupFilter query "'.$filter.'"');
            return false;
        }

        $userLdapAttributes->groups = array();
        do {
            $attributes = @ldap_get_attributes($connect, $entry);
            if (isset($attributes[$grpProp]) && $attributes[$grpProp]['count'] > 0) {
                $userLdapAttributes->groups[] = $attributes[$grpProp][0];
            }
        } while ($entry = @ldap_next_entry($connect, $entry));
        return true;
    }

    /**
     * open the connection to the ldap server
     *
     * @throws Exception
     */
    protected function _getLinkId() : Connection
    {
        //ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);

        if ($this->parameters['tlsMode'] != '') {
            $this->setTlsOptions();
        }

        $connect = @ldap_connect($this->uriConnect);
        if (!$connect) {
            $this->log(self::LOG_ERROR, 'ldap connection: impossible to connect to ldap with the given uri "'.$this->uriConnect.'"');
            throw new Exception('ldap connection: impossible to connect to ldap');
        }

        ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, $this->parameters['protocolVersion']);
        ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);

        $networkTimeout = (int) $this->parameters['networkTimeout'];
        if ($networkTimeout > 0) {
            ldap_set_option($connect, LDAP_OPT_NETWORK_TIMEOUT, $networkTimeout);
        }
        $timeLimit = (int) $this->parameters['timeLimit'];
        if ($timeLimit > 0) {
            // time limit for the server
            ldap_set_option($connect, LDAP_OPT_TIMELIMIT, $timeLimit);
            // time limit for the client, a bit higher to let the server answer
            ldap_set_option($connect, LDAP_OPT_TIMEOUT, $timeLimit + 5);
        }

        if ($this->parameters['tlsMode'] == 'starttls') {
            if (!@ldap_start_tls($connect)) {
                $this->log(self::LOG_ERROR, 'ldap connection: impossible to start TLS connection to ' . $this->uriConnect, $connect);
                ldap_close($connect);
                throw new Exception('ldap connection: impossible to start TLS connection');
            }
        }

        return $connect;
    }

    /**
     * Set TLS options.
     *
     * These options are global to the PHP process (limitation of PHP and libldap)
     */
    protected function setTlsOptions(): void
    {
        if ($this->parameters['clientTLSCACertificateFile']) {
            ldap_set_option(null, LDAP_OPT_X_TLS_CACERTFILE, $this->parameters['clientTLSCACertificateFile']);
        }
        if ($this->parameters['clientTLSCertificateFile']) {
            ldap_set_option(null, LDAP_OPT_X_TLS_CERTFILE, $this->parameters['clientTLSCertificateFile']);
        }
        if ($this->parameters['clientTLSKeyFile']) {
            ldap_set_option(null, LDAP_OPT_X_TLS_KEYFILE, $this->parameters['clientTLSKeyFile']);
        }

        // the certificate of the server must always be verified, whatever
        // the TLS_REQCERT value into ldap.conf or the LDAPTLS_REQCERT environment variable.
        ldap_set_option(null, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_DEMAND);

        ldap_set_option(null, LDAP_OPT_X_TLS_PROTOCOL_MIN , LDAP_OPT_X_TLS_PROTOCOL_TLS1_2);
        if (defined('LDAP_OPT_X_TLS_PROTOCOL_MAX') && defined('LDAP_OPT_X_TLS_PROTOCOL_TLS1_3')) {
            ldap_set_option(null, LDAP_OPT_X_TLS_PROTOCOL_MAX , LDAP_OPT_X_TLS_PROTOCOL_TLS1_3);
        }
        // LDAP_OPT_X_TLS_NEWCTX (0x600f) - force libldap to rebuild
        // the TLS context from the options we just set
        // FIXME it doesn't work with PHP 8. perhaps in futur versions?
        //ldap_set_option(NULL, 0x600f, 0);
    }

    /**
     * open the connection to the ldap server
     * and bind to the admin user
     * @return Connection the ldap connection
     * @throws Exception
     */
    protected function _bindLdapAdminUser(): Connection
    {
        if ($this->parameters['adminUserDn'] != '' && (string)$this->parameters['adminPassword'] === '') {
            // a bind with a DN and without password is an unauthenticated bind
            $this->log(self::LOG_ERROR, 'ldap configuration: password of the admin user is missing');
            throw new Exception('ldap configuration: password of the admin user is missing');
        }

        $connect = $this->_getLinkId();
        if ($this->parameters['adminUserDn'] == '') {
            $bind = @ldap_bind($connect);
        } else {
            $bind = @ldap_bind($connect, $this->parameters['adminUserDn'], $this->parameters['adminPassword']);
        }
        if (!$bind) {
            if ($this->parameters['adminUserDn'] == '') {
                $this->log(self::LOG_ERROR, 'ldap connection: impossible to authenticate to ldap as anonymous admin user', $connect);
            } else {
                $this->log(self::LOG_ERROR, 'ldap connection: impossible to authenticate to ldap with admin user '.$this->parameters['adminUserDn'], $connect);
            }
            ldap_close($connect);
            throw new Exception('ldap connection: impossible to authenticate to ldap with the main user');
        }
        return $connect;
    }

    /**
     * Indicates if the password should be set by the server with
     * the "Password Modify Extended Operation" (RFC 3062)
     */
    protected function usePasswordModifyExtendedOperation(): bool
    {
        return strtoupper($this->parameters['passwordLdapHashAlgo']) == 'EXOP';
    }

    /**
     * Indicates if passwords are stored into the unicodePwd attribute of Active Directory
     */
    protected function useActiveDirectoryPassword(): bool
    {
        return strtoupper($this->parameters['passwordLdapHashAlgo']) == 'AD';
    }

    /**
     * Encodes a password for the unicodePwd attribute of Active Directory
     *
     * The password should be surrounded by double quotes, and encoded in UTF-16LE
     *
     * @param string $password the password, encoded in UTF-8
     * @return string
     * @throws Exception if the password is not a valid UTF-8 string
     */
    protected function encodeActiveDirectoryPassword(string $password): string
    {
        if (!preg_match('//u', $password)) {
            throw new Exception('ldap: the password is not a valid UTF-8 string');
        }
        return iconv('UTF-8', 'UTF-16LE', '"'.$password.'"');
    }

    /**
     * Sets the password of a new Active Directory account, and enables the account.
     *
     * The account is deleted if the password cannot be set (password policy...)
     *
     * @param Connection $connectAdmin
     * @param string $dn DN of the new user
     * @param string $login
     * @param string $password
     * @param array $ldapAttributes attributes given to create the account
     * @throws Exception
     */
    protected function setActiveDirectoryPasswordOfNewUser(Connection $connectAdmin, string $dn, string $login, string $password, array $ldapAttributes): void
    {
        if (!@ldap_mod_replace($connectAdmin, $dn, array(
            "unicodePwd" => $this->encodeActiveDirectoryPassword($password)
        ))) {
            $msg = 'ldap: error when trying to set the password of the new user "'.$login.'"';
            $this->log(self::LOG_ERROR, $msg, $connectAdmin);
            // we don't want an account without password
            @ldap_delete($connectAdmin, $dn);
            throw new Exception($msg);
        }

        // enable the account, keeping other flags given into newUserLdapAttributes
        $uac = self::AD_UAC_NORMAL_ACCOUNT;
        foreach ($ldapAttributes as $attr => $value) {
            if (strtolower($attr) == 'useraccountcontrol') {
                $uac = (int) (is_array($value) ? $value[0] : $value);
                break;
            }
        }
        $uac &= ~(self::AD_UAC_ACCOUNTDISABLE | self::AD_UAC_PASSWD_NOTREQD);

        if (!@ldap_mod_replace($connectAdmin, $dn, array("userAccountControl" => (string) $uac))) {
            $msg = 'ldap: error when trying to enable the account of the new user "'.$login.'"';
            $this->log(self::LOG_ERROR, $msg, $connectAdmin);
            @ldap_delete($connectAdmin, $dn);
            throw new Exception($msg);
        }
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
        $algo = strtoupper($this->parameters['passwordLdapHashAlgo']);
        switch($algo) {
            case 'CRYPT':
                // SHA-512 crypt. The salt should contain only [a-zA-Z0-9./] characters
                $salt = substr(strtr(base64_encode(random_bytes(12)), '+', '.'), 0, 16);
                $hash = crypt($password, '$6$rounds=50000$'.$salt.'$');
                if (strpos($hash, '$6$') !== 0) {
                    throw new Exception("ldap hash password: SHA-512 crypt is not supported");
                }
                return '{CRYPT}'.$hash;
            case 'SSHA':
                $salt = $this->generateSalt();
                return "{SSHA}" . base64_encode(sha1($password . $salt, true) . $salt);
            case 'SHA':
                $this->log(self::LOG_WARNING, 'ldap hash password: the SHA algorithm is weak, you should use CRYPT, EXOP or SSHA');
                return "{SHA}" . base64_encode(sha1($password, true));
            case 'MD5':
                $this->log(self::LOG_WARNING, 'ldap hash password: the MD5 algorithm is weak, you should use CRYPT, EXOP or SSHA');
                return "{MD5}".base64_encode(md5($password, true));
            case 'SMD5':
                $this->log(self::LOG_WARNING, 'ldap hash password: the SMD5 algorithm is weak, you should use CRYPT, EXOP or SSHA');
                $salt = $this->generateSalt();
                return "{SMD5}" . base64_encode(md5($password . $salt, true) . $salt);
            case '':
                $this->log(self::LOG_NOTICE, 'ldap hash password: the password is not hashed by the library');
                return $password;
            default:
                // EXOP and AD are not supported here: the password is never hashed by the library
                throw new Exception("ldap hash password: Unknown algorithm '".$this->parameters['passwordLdapHashAlgo']."'");
        }
    }

    /**
     * Generates a cryptographic salt string for password handling.
     *
     * @return string random bytes, of the length given by passwordLdapSaltLength (8 bytes minimum)
     */
    protected function generateSalt() : string
    {
        $length = max(8, (int) $this->parameters['passwordLdapSaltLength']);
        return random_bytes($length);
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
     * @param int $type The log type (one of LOG_* constants), used to determine the logger method.
     * @param string $message The message to be logged.
     * @param Connection|null $connect An optional connection object to retrieve LDAP error details.
     * @return void
     */
    protected function log(int $type, string $message, ?Connection $connect = null)
    {
        if (!$this->logger) {
            return;
        }

        // the message may contain values given by users: control characters
        // are escaped to avoid forged log lines
        $message = addcslashes($message, "\0..\37\177");

        if ($connect) {
            $message = $this->getLdapError($connect, $message);
        }

        $method = self::$loggerMethods[$type] ?? 'info';
        $this->logger->$method($message);
    }
}
