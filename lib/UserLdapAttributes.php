<?php
/**
 * @author     Laurent Jouanneau
 * @copyright  2019-2023 Laurent Jouanneau
 * @license   MIT
 */
namespace Jelix\Ldap;


class UserLdapAttributes {

    public $dn = '';

    /**
     * Ldap attributes. Only the first value is given for multi-valued attributes
     * @var array
     */
    public $ldapAttributes = array();

    /**
     * All values of ldap attributes. Each item is an array of values.
     * @var array
     */
    public $ldapAttributesValues = array();

    public $userAttributes = array();

    /**
     * Groups are loaded only when the user authentication
     * @var null|array
     */
    public $groups = null;

}
