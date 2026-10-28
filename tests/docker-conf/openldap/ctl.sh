#!/bin/bash
COMMAND="$1"

#if [ "$COMMAND" -eq "" ]; then
#    echo "Error: command is missing"
#    exit 1;
#fi

case $COMMAND in
    reset)
      ldapdelete -x -c -D cn=admin,dc=tests,dc=jelix -w passjelix -f /customldif/reset/ldap_delete.ldif
      ldapadd -x -c -D cn=admin,dc=tests,dc=jelix -w passjelix -f /customldif/prepopulate/ldap_users.ldif
      ;;
    setup)
      ldapadd -x -D cn=admin,dc=tests,dc=jelix -w passjelix -f /customldif/prepopulate/ldap_users.ldif
      #ldapsearch -x -D cn=admin,dc=tests,dc=jelix -w passjelix -b "dc=tests,dc=jelix" "(objectClass=*)"
      ;;
    showusers)
      ldapsearch -x -D cn=admin,dc=tests,dc=jelix -w passjelix -b "dc=tests,dc=jelix" "(objectClass=*)"
      ;;
    setup-tls-never)
      # configuration to not ask client certificate
      ldapmodify -Y EXTERNAL -H ldapi:/// -f /customldif/mod_tls_never.ldif
      ;;
    setup-tls-allow)
      # configuration to ask an optional client certificate
      ldapmodify -Y EXTERNAL -H ldapi:/// -f /customldif/mod_tls_allow.ldif
      ;;
    setup-tls-demand)
      # configuration to ask a client certificate
      ldapmodify -Y EXTERNAL -H ldapi:/// -f /customldif/mod_tls_demand.ldif
      ;;
    *)
        echo "wrong command"
        exit 2
        ;;
esac
