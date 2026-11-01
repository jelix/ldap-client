# -----------------
# Samba service, configured as an Active Directory domain controller
# -----------------
FROM debian:trixie

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update && apt-get install -y --no-install-recommends \
      samba \
      samba-ad-dc \
      samba-ad-provision \
      samba-dsdb-modules \
      winbind \
      ldb-tools \
      ldap-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && rm -f /etc/samba/smb.conf

COPY entrypoint.sh /entrypoint.sh
COPY ctl.sh /bin/ctl.sh
RUN chmod 755 /entrypoint.sh /bin/ctl.sh

# Expose ldap and ldaps ports
EXPOSE 389 636

ENTRYPOINT ["/entrypoint.sh"]

CMD ["samba", "--foreground", "--no-process-group", "--debug-stdout"]
