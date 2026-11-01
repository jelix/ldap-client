#!/bin/bash

set -e

SAMBA_REALM="${SAMBA_REALM:-AD.JELIX}"
SAMBA_DOMAIN="${SAMBA_DOMAIN:-ADJELIX}"
SAMBA_HOSTNAME="${SAMBA_HOSTNAME:-dc1}"

if [[ ! -f /var/lib/samba/private/sam.ldb ]]; then

    if [[ -z "$SAMBA_ADMIN_PASSWORD" ]]; then
        echo >&2 "Error: Container not configured and SAMBA_ADMIN_PASSWORD not set."
        exit 1
    fi

    rm -f /etc/samba/smb.conf

    # ACL of the sysvol are stored into a tdb file instead of extended
    # attributes, so the container doesn't need privileges
    samba-tool domain provision \
        --server-role=dc \
        --realm="$SAMBA_REALM" \
        --domain="$SAMBA_DOMAIN" \
        --host-name="$SAMBA_HOSTNAME" \
        --adminpass="$SAMBA_ADMIN_PASSWORD" \
        --dns-backend=NONE \
        --use-rfc2307 \
        --option="interfaces = lo eth0" \
        --option="bind interfaces only = yes" \
        --option="posix:eadb = /var/lib/samba/private/eadb.tdb" \
        --option="vfs objects = dfs_samba4 acl_xattr xattr_tdb" \
        --option="dns update command = /bin/true"

    # by default, the previous password is still accepted during 60 minutes
    # after a change. We don't want it for tests.
    sed -i '/^\[global\]/a \
	old password allowed period = 0' /etc/samba/smb.conf

    if [[ -n "$SAMBA_TLS_KEY_FILENAME" && -d /customcerts ]]; then
        mkdir -p /var/lib/samba/private/tls
        cp /customcerts/$SAMBA_TLS_KEY_FILENAME /var/lib/samba/private/tls/key.pem
        cp /customcerts/$SAMBA_TLS_CRT_FILENAME /var/lib/samba/private/tls/cert.pem
        cp /customcerts/$SAMBA_TLS_CA_CRT_FILENAME /var/lib/samba/private/tls/ca.pem
        chmod 0600 /var/lib/samba/private/tls/key.pem
        chmod 0644 /var/lib/samba/private/tls/cert.pem /var/lib/samba/private/tls/ca.pem

        sed -i '/^\[global\]/a \
	tls enabled = yes\
	tls keyfile = /var/lib/samba/private/tls/key.pem\
	tls certfile = /var/lib/samba/private/tls/cert.pem\
	tls cafile = /var/lib/samba/private/tls/ca.pem' /etc/samba/smb.conf
    fi

    # creates organizational units, users and groups used by tests
    /bin/ctl.sh setup
fi

exec "$@"
