#!/bin/bash
COMMAND="$1"

BASE_DN="DC=ad,DC=jelix"
# the database is modified directly, so the server doesn't need to be started
SAMBA_TOOL_OPTS="-H /var/lib/samba/private/sam.ldb"

function deleteTestUsers() {
    for user in john jane testad testadweak; do
        samba-tool user delete $user $SAMBA_TOOL_OPTS >/dev/null 2>&1
    done
    samba-tool group delete testgroup $SAMBA_TOOL_OPTS >/dev/null 2>&1
}

function setup() {
    samba-tool ou create "OU=People,$BASE_DN" $SAMBA_TOOL_OPTS >/dev/null 2>&1
    samba-tool ou create "OU=Guests,$BASE_DN" $SAMBA_TOOL_OPTS >/dev/null 2>&1

    samba-tool user create john 'Passjohn-123' --userou=OU=People \
        --given-name=John --surname=Doe --mail-address=john@jelix.org $SAMBA_TOOL_OPTS
    samba-tool user create jane 'Passjane-123' --userou=OU=People \
        --given-name=Jane --surname=Doe --mail-address=jane@jelix.org $SAMBA_TOOL_OPTS

    samba-tool group add testgroup $SAMBA_TOOL_OPTS
    samba-tool group addmembers testgroup john $SAMBA_TOOL_OPTS
}

case $COMMAND in
    setup)
      setup
      ;;
    reset)
      deleteTestUsers
      setup
      ;;
    showusers)
      ldbsearch -H /var/lib/samba/private/sam.ldb -b "$BASE_DN" \
        "(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit))" \
        dn sAMAccountName displayName mail userAccountControl member
      ;;
    *)
        echo "wrong command"
        exit 2
        ;;
esac
