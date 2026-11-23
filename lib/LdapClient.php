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
class LdapClient
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

    protected static $tlsModes = array('', 'starttls', 'ldaps');

    public const defaultParameters = array(
        'hostname'      =>  'localhost',
        'tlsMode'       => '', // TLS mode: '' (or 'none'), 'starttls', 'ldaps'
        'port'          =>  389, // Port number
        'adminUserDn'      => '', // Admin user DN
        'adminPassword'      => '', // Admin user password
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
        'featureGroupLoad' => false,
        'clientTLSCACertificateFile'=> '',
        'featureClientTLSCertificate' => false, // true to use the client certificate
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

    public const ERROR_ANONYMOUS_AUTH = 1;
    public const ERROR_USER_NOT_FOUND = 2;
    public const ERROR_MISSING_BIND_ATTRIBUTE = 3;
    public const ERROR_WRONG_DN_OR_PASSWORD = 4;

    /**
     * @var int one of ERROR_* const value
     */
    protected $latestErrorCode = 0;

    public const TEST_MODE_OFF = 0;
    public const TEST_MODE_IGNORE_CONNECTION = 1;
    public const TEST_MODE_IGNORE_USER_SEARCH = 2;
    public const TEST_MODE_IGNORE_GROUP_SEARCH = 4;

    /**
     * @param array $params configuration parameters
     * @param int $testMode a combination of TEST_MODE_* constants
     */
    public function __construct(array $params, ?LoggerInterface $logger = null, int $testMode = 0)
    {
        if (!extension_loaded('ldap')) {
            throw new Exception('PHP Ldap extension is not activated', 1);
        }

        $this->logger = $logger;

        // default ldap parameters
        $this->parameters = $params;

        // iterate each default parameter and apply it to actual params if missing in $params.
        foreach (self::defaultParameters as $name => $value) {
            if (!isset($this->parameters[$name]) || $this->parameters[$name] === '') {
                $this->parameters[$name] = $value;
            }
        }

        $tlsMode = strtolower(trim((string)$this->parameters['tlsMode']));
        if ($tlsMode == 'none') {
            $tlsMode = '';
        }
        if (!in_array($tlsMode, self::$tlsModes, true)) {
            throw new Exception('ldap configuration: invalid tlsMode value "'.$this->parameters['tlsMode'].'". Possible values: "" (or "none"), "starttls", "ldaps"', 2);
        }
        $this->parameters['tlsMode'] = $tlsMode;

        if (!isset($this->parameters['searchUserBaseDN']) || $this->parameters['searchUserBaseDN'] == '') {
            if ($testMode & self::TEST_MODE_IGNORE_USER_SEARCH) {
                $this->parameters['searchUserBaseDN'] = array();
            }
            else {
                throw new Exception('ldap configuration: base DN for search is missing', 3);
            }
        }

        if (!is_array($this->parameters['searchUserBaseDN'])) {
            $this->parameters['searchUserBaseDN'] = array($this->parameters['searchUserBaseDN']);
        }

        if (!isset($this->parameters['searchUserFilter']) || $this->parameters['searchUserFilter'] == '') {
            if ($testMode & self::TEST_MODE_IGNORE_USER_SEARCH) {
                $this->parameters['searchUserFilter'] = array();
            }
            else {
                throw new Exception('ldap configuration: search filter missing', 4);
            }
        }
        if (!is_array($this->parameters['searchUserFilter'])) {
            $this->parameters['searchUserFilter'] = array($this->parameters['searchUserFilter']);
        }

        $cf = count($this->parameters['searchUserFilter']);
        $cb = count($this->parameters['searchUserBaseDN']);
        if ($cf != $cb) {
            if ($cf > 1 && $cb > 1) {
                throw new Exception('ldap configuration: wrong number of searchUserFilter and searchUserBaseDN values', 5);
            }
            if ($cf === 1) {
                $this->parameters['searchUserFilter'] = array_fill(0, $cb, $this->parameters['searchUserFilter'][0]);
            }
            else if ($cb === 1) {
                $this->parameters['searchUserBaseDN'] = array_fill(0, $cf, $this->parameters['searchUserBaseDN'][0]);
            }
        }

        $this->parameters['searchAttributes'] = self::parseSearchAttributes($this->parameters['searchAttributes'] ?? '');

        if ($this->parameters['featureGroupLoad'] && !($testMode & self::TEST_MODE_IGNORE_GROUP_SEARCH)) {
            foreach (array('searchGroupFilter', 'searchGroupProperty', 'searchGroupBaseDN') as $name) {
                if (trim((string) $this->parameters[$name]) === '') {
                    throw new Exception('ldap configuration: '.$name.' config parameter is missing, it is required when featureGroupLoad is enabled', 8);
                }
            }
        }

        if ($this->parameters['featureClientTLSCertificate'] && !($testMode & self::TEST_MODE_IGNORE_CONNECTION)) {
            if (trim((string) $this->parameters['clientTLSCertificateFile']) === ''
                || trim((string) $this->parameters['clientTLSKeyFile']) === ''
            ) {
                throw new Exception('ldap configuration: clientTLSCertificateFile and clientTLSKeyFile config parameters are required when featureClientTLSCertificate is enabled', 13);
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
    }

    /**
     * Parse the `searchAttributes` configuration parameters
     *
     * @param string|array $searchAttributes
     * @return array list of ldap attributes as keys, and user fields as values
     */
    public static function parseSearchAttributes(string|array $searchAttributes): array
    {
        if ($searchAttributes == '') {
            return self::$defaultAttributes;
        }

        if (is_string($searchAttributes)) {
            $attrs = explode(",", $searchAttributes);
            $searchAttributes = array();
            foreach ($attrs as $attr) {
                if (strpos($attr, ':') === false) {
                    $attr = trim($attr);
                    if ($attr !== '') {
                        $searchAttributes[$attr] = $attr;
                    }
                } else {
                    $attr = explode(':', $attr, 2);
                    $searchAttributes[trim($attr[0])] = trim($attr[1]);
                }
            }
        } else if (is_array($searchAttributes)) {
            foreach($searchAttributes as $ldapAttr => $userField) {
                if ($userField == '=') {
                    $searchAttributes[$ldapAttr] = $ldapAttr;
                }
            }
        }

        return $searchAttributes;
    }

    /**
     * Indicates which features are activated into the library
     *
     * @return int a combination of FEATURE_* constants
     */
    public function getFeatures() : int
    {
        $feat = 0;
        if ($this->parameters['featureGroupLoad']) {
            $feat |= self::FEATURE_GROUP_LOAD;
        }
        return $feat;
    }

    public function hasFeature(int $feature) : bool
    {
        switch($feature) {
            case self::FEATURE_GROUP_LOAD:
                return $this->parameters['featureGroupLoad'];
        }
        return false;
    }

    /**
     * Try to connect to the ldap server and bind with the admin credentials.
     * Can be used to implement a "test connection" button of an UI for example.
     *
     * @return array
     */
    public function testConnection()
    {
        try {
            $connectAdmin = $this->_bindLdapAdminUser();
            ldap_close($connectAdmin);
            return array('result' => true);
        } catch(Exception $e) {
            return array(
                'result' => false,
                'errorCode' => $e->getCode(),
                'errorMessage' => $e->getMessage()
            );
        }
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
     * Verify the password of a user
     *
     * Note: the given login may differ from the login stored into the
     * directory (case, spaces...), as ldap comparisons are often case-insensitive.
     * Use the returned attributes to know the real login of the user.
     *
     * @param string $login
     * @param string $password
     * @return false|UserLdapAttributes
     * @see getLatestErrorCode() to get the error code to know why the authentication fails
     * @throws Exception
     */
    public function verifyAuthentication(string $login, string $password, bool $loadAlsoGroups = true): false|UserLdapAttributes
    {
        $this->latestErrorCode = 0;
        $login = trim($login, " ");
        if (trim($password) == '' || trim($login) == '') {
            // we don't want Unauthenticated Authentication
            // and Anonymous Authentication
            // https://tools.ietf.org/html/rfc4513#section-5.1
            $this->latestErrorCode = self::ERROR_ANONYMOUS_AUTH;
            return false;
        }

        $connectAdmin = $this->_bindLdapAdminUser();
        try {
            // see if the user exists into the ldap directory
            $attributes = $this->searchLdapUserAttributes($connectAdmin, $login);
            if ($attributes === false) {
                $this->log(self::LOG_DEBUG, 'ldap authentication: user '.$login.' not found into the ldap');
                $this->latestErrorCode = self::ERROR_USER_NOT_FOUND;
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
                $this->latestErrorCode = self::ERROR_MISSING_BIND_ATTRIBUTE;
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
                    $this->latestErrorCode = self::ERROR_WRONG_DN_OR_PASSWORD;
                    $this->log(self::LOG_DEBUG, 'ldap authentication: cannot authenticate to ldap with given base DN for the login ' . $login. '. Wrong DN or password');
                    $this->log(self::LOG_NOTICE, 'ldap authentication: failed to connect with "'.$bindDn.'"', $connect);
                    return false;
                }
            } finally {
                ldap_close($connect);
            }

            if ($loadAlsoGroups) {
                // retrieve the user groups (if featureGroupLoad is enabled)
                $this->searchUserGroups($connectAdmin, $attributes, $login);
            }
            return $attributes;
        } finally {
            ldap_close($connectAdmin);
        }
        return false;
    }

    /**
     * get the error code of the reason why verifyAuthentication() has failed
     *
     * @return int one of ERROR_* const value
     */
    public function getLatestErrorCode(): int
    {
        return $this->latestErrorCode;
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
                throw new Exception($msg, 46);
            }

            $count = ldap_count_entries($connect, $search);
            if ($count > 1) {
                $msg = 'ldap: several entries match the login "'.$login.'" with the base DN "'.$baseDn.'"';
                $this->log(self::LOG_ERROR, $msg.' and filter "'.$filter.'"');
                throw new Exception($msg, 47);
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
            throw new Exception($msg, 48);
        }
        return $dn;
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
            throw new Exception('ldap error during group search for "'.$login.'"', 49);
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
            throw new Exception('ldap connection: impossible to connect to ldap', 70);
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
                throw new Exception('ldap connection: impossible to start TLS connection', 71);
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
        if ($this->parameters['featureClientTLSCertificate']) {
            if ($this->parameters['clientTLSCertificateFile']) {
                ldap_set_option(null, LDAP_OPT_X_TLS_CERTFILE, $this->parameters['clientTLSCertificateFile']);
            }
            if ($this->parameters['clientTLSKeyFile']) {
                ldap_set_option(null, LDAP_OPT_X_TLS_KEYFILE, $this->parameters['clientTLSKeyFile']);
            }
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
            throw new Exception('ldap configuration: password of the admin user is missing', 10);
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
            throw new Exception('ldap connection: impossible to authenticate to ldap with the admin user', 72);
        }
        return $connect;
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
