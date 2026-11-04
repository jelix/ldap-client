<?php
/**
 * @author     Laurent Jouanneau
 * @copyright  2023-2026 Laurent Jouanneau
 * @license   MIT
 */
namespace Jelix\Ldap;

/**
 * Exception for our library
 *
 * Error codes:
 * - 1 to 19 : configuration
 * - 20 to 39 : logical or parameter error
 * - 40 to 69: ldap error
 * - 70 to 89: connection/authentication error
 */
class Exception extends \Exception
{

}

