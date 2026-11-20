# Provides the disposable Linux runtime for source-matched Exim qualification.
FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d
ENV GOTOOLCHAIN=go1.27.4

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl dnsmasq dpkg-dev gpgv iproute2 \
      libdb-dev libfile-fcntllock-perl libgnutls28-dev libidn11-dev libidn2-dev libldap2-dev libpcre2-dev \
      libsqlite3-dev netcat-openbsd patch python3 systemd systemd-sysv \
 && rm -f /etc/systemd/system/multi-user.target.wants/dnsmasq.service \
 && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
