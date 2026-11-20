<?php
/**
 * @author     Laurent Jouanneau
 * @copyright  2019-2026 Laurent Jouanneau
 * @license   MIT
 */

namespace Jelix\Ldap;

use LDAP\Connection;
use Psr\Log\LoggerInterface;

/**
 * Manage user accounts into an ldap directory: creation, modification,
 * deletion, password change.
 *
 * It provides also all features of LdapClient (authentication, user search...)
 */
class LdapUserManager extends LdapClient
{
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

    /**
     * Default values of configuration parameters used only by the user manager
     */
    public const userManagerDefaultParameters = array(
        'newUserDN' => '',
        'passwordLdapHashAlgo' => '',
        'passwordLdapSaltLength' => 8, // salt length in bytes
        'featureCreateUser' => false,
        'featureUpdateUser' => false,
        'featureDeleteUser' => false,
        'featureChangePassword' => false,
    );

    /**
     * @param array $params configuration parameters
     */
    public function __construct(array $params, ?LoggerInterface $logger = null, $testMode = false)
    {
        parent::__construct($params, $logger, $testMode);

        foreach (self::userManagerDefaultParameters as $name => $value) {
            if (!isset($this->parameters[$name]) || $this->parameters[$name] === '') {
                $this->parameters[$name] = $value;
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
            throw new Exception('ldap configuration: newUserLdapAttributes should be a string or an array', 6);
        }

        if ($this->parameters['newUserDN'] == '' && $this->parameters['featureCreateUser']) {
            throw new Exception('ldap configuration: no newUserDN config parameter', 7);
        }

        if ($this->useActiveDirectoryPassword() && $this->parameters['tlsMode'] == '' && !$testMode) {
            throw new Exception('ldap configuration: Active Directory refuses to set passwords on an unencrypted connection. tlsMode should be "starttls" or "ldaps" when passwordLdapHashAlgo is "AD"', 9);
        }
    }

    /**
     * Indicates which features are activated into the library
     *
     * @return int a combination of FEATURE_* constants
     */
    public function getFeatures() : int
    {
        $feat = parent::getFeatures();
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

    public function hasFeature(int $feature) : bool
    {
        switch($feature) {
            case self::FEATURE_CHANGE_PASSWORD:
                return $this->parameters['featureChangePassword'];
            case self::FEATURE_CREATE_USER:
                return $this->parameters['featureCreateUser'];
            case self::FEATURE_DELETE_USER:
                return $this->parameters['featureDeleteUser'];
            case self::FEATURE_UPDATE_USER:
                return $this->parameters['featureUpdateUser'];
        }
        return parent::hasFeature($feature);
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
                throw new Exception($msg, 40);
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
            throw new Exception($msg, 20);
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
            throw new Exception($msg, 41);
        }

        $connectAdmin = $this->_bindLdapAdminUser();
        try {
            if (!@ldap_add($connectAdmin, $dn, $ldapAttributes)) {
                $msg = 'ldap: error when trying to create a user "'.$login.'"';
                $this->log(self::LOG_ERROR, $msg, $connectAdmin);
                throw new Exception($msg, 42);
            }

            if ($useExop && @ldap_exop_passwd($connectAdmin, $dn, '', $password) === false) {
                $msg = 'ldap: error when trying to set the password of the new user "'.$login.'"';
                $this->log(self::LOG_ERROR, $msg, $connectAdmin);
                // we don't want an account without password
                @ldap_delete($connectAdmin, $dn);
                throw new Exception($msg, 43);
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
                throw new Exception($msg, 44);
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
                throw new Exception($msg, 45);
            }
            return true;
        } finally {
            ldap_close($connectAdmin);
        }
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
                throw new Exception($msg, 21);
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
            throw new Exception('ldap: the password is not a valid UTF-8 string', 22);
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
            throw new Exception($msg, 50);
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
            throw new Exception($msg, 51);
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
                    throw new Exception("ldap hash password: SHA-512 crypt is not supported", 11);
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
                throw new Exception("ldap hash password: Unknown algorithm '".$this->parameters['passwordLdapHashAlgo']."'", 12);
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
}
