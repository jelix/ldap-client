<?php

namespace Jelix\Ldap;

class LdapMigration
{
    /**
     * Migrate the configuration from the old format used by the ldapdao module (version <=2.2) to our format.
     * @param array $configuration
     * @return array
     */
    public static function migrateLdapDaoConfiguration(array $configuration): array
    {
        return self::migrateMultiauthConfiguration($configuration);
    }

    /**
     * Migrate the configuration from the format used by the Multiauth module (version <= 1.2) to our format.
     * @param array $configuration
     * @return array
     */
    public static function migrateMultiauthConfiguration(array $configuration): array
    {
        if (isset($configuration['bindUserDN'])) {
            $configuration['bindAttribute'] = self::getBindAttributeFromBindUserDN(
                $configuration['bindUserDN'],
                $configuration['searchAttributes'] ?? ''
            );
            unset($configuration['bindUserDN']);
        } else if (!isset($configuration['bindAttribute']) || $configuration['bindAttribute'] === '') {
            $configuration['bindAttribute'] = 'dn';
        }

        // Multiauth and ldapdao do not support creation, deletion and modification of users
        $configuration['featureCreateUser'] = false;
        $configuration['featureUpdateUser'] = false;
        $configuration['featureDeleteUser'] = false;

        // groups were loaded as soon as a group filter was given
        $configuration['featureGroupLoad'] = (
            trim((string) ($configuration['searchGroupFilter'] ?? '')) !== ''
            && trim((string) ($configuration['searchGroupProperty'] ?? '')) !== ''
        );
        if ($configuration['featureGroupLoad'] && trim((string) ($configuration['searchGroupBaseDN'] ?? '')) === '') {
            // the base DN is now required: we take the base DN used to search users
            $userBaseDN = $configuration['searchUserBaseDN'] ?? '';
            if (is_array($userBaseDN)) {
                $userBaseDN = reset($userBaseDN);
            }
            $configuration['searchGroupBaseDN'] = (string) $userBaseDN;
            if ($configuration['searchGroupBaseDN'] === '') {
                $configuration['featureGroupLoad'] = false;
            }
        }

        return $configuration;
    }

    /**
     * Find the ldap attribute containing the DN to bind, from the bindUserDN templates
     *
     * @param string|array $bindUserDN one or several DN templates
     * @param string|array $searchAttributes
     * @return string the name of the ldap attribute
     */
    protected static function getBindAttributeFromBindUserDN(string|array $bindUserDN, string|array $searchAttributes): string
    {
        $templates = array();
        foreach ((array) $bindUserDN as $template) {
            $template = trim((string) $template);
            if ($template !== '') {
                $templates[] = $template;
            }
        }

        // case `$ldapattr`: the attribute contains the full DN
        foreach ($templates as $template) {
            if ($template[0] == '$' && strlen($template) > 1) {
                return substr($template, 1);
            }
        }

        // case `%%LOGIN%%`: the login is the DN, so we take the attribute mapped to the login
        if (in_array('%%LOGIN%%', $templates, true)) {
            $attributes = self::parseSearchAttributes($searchAttributes);
            foreach ($attributes as $ldapAttr => $userField) {
                if (trim((string) $userField) == 'login') {
                    return $ldapAttr;
                }
            }
            return 'dn';
        }

        // cases `cn=%?%,ou=users,...` and `cn=%%LOGIN%%,ou=users,...`: we cannot know
        // which attribute contains the DN, so we use the DN of the ldap entry
        return 'dn';
    }

    /**
     * @param string|array $searchAttributes
     * @return array list of ldap attributes as keys, and user fields as values
     */
    protected static function parseSearchAttributes(string|array $searchAttributes): array
    {
        if (is_array($searchAttributes)) {
            return $searchAttributes;
        }

        $attributes = array();
        foreach (explode(',', $searchAttributes) as $attr) {
            if (strpos($attr, ':') === false) {
                $attr = trim($attr);
                if ($attr !== '') {
                    $attributes[$attr] = $attr;
                }
            } else {
                $attr = explode(':', $attr, 2);
                $attributes[trim($attr[0])] = trim($attr[1]);
            }
        }
        return $attributes;
    }
}
