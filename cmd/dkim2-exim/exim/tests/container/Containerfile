# Provides the disposable Linux runtime for source-matched Exim qualification.
FROM golang@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl dnsmasq dpkg-dev gpgv iproute2 \
      libdb-dev libfile-fcntllock-perl libgnutls28-dev libidn11-dev libidn2-dev libldap2-dev libpcre2-dev \
      libsqlite3-dev netcat-openbsd patch python3 systemd systemd-sysv \
 && rm -f /etc/systemd/system/multi-user.target.wants/dnsmasq.service \
 && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
