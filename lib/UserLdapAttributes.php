<?php
/**
 * @author     Laurent Jouanneau
 * @copyright  2019-2023 Laurent Jouanneau
 * @license   MIT
 */
namespace Jelix\Ldap;


class UserLdapAttributes {

    public $dn = '';

    public $ldapAttributes = array();

    public $userAttributes = array();

    /**
     * Groups are loaded only when the user authentication
     * @var null|array
     */
    public $groups = null;

}
