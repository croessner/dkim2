# Provides the disposable Linux runtime for source-matched Exim qualification.
FROM golang:1.27.0-trixie@sha256:df98008ecd2b0ecc9f0a94d1b07e3564a9c92b555369b33d9b5f60d0765b2db7
ENV GOEXPERIMENT=runtimesecret
ENV GOTOOLCHAIN=go1.27.0

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl dnsmasq dpkg-dev gpgv iproute2 \
      libdb-dev libfile-fcntllock-perl libgnutls28-dev libidn11-dev libidn2-dev libldap2-dev libpcre2-dev \
      libsqlite3-dev netcat-openbsd patch python3 systemd systemd-sysv \
 && rm -f /etc/systemd/system/multi-user.target.wants/dnsmasq.service \
 && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
