# Provides the disposable Linux runtime for source-matched Exim qualification.
FROM golang:1.27.2-trixie@sha256:47667934874913a449b96faa7ef4777fa285d9ec29126ee80ed61c45b7cccf0e
ENV GOEXPERIMENT=runtimesecret
ENV GOTOOLCHAIN=go1.27.2

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl dnsmasq dpkg-dev gpgv iproute2 \
      libdb-dev libfile-fcntllock-perl libgnutls28-dev libidn11-dev libidn2-dev libldap2-dev libpcre2-dev \
      libsqlite3-dev netcat-openbsd patch python3 systemd systemd-sysv \
 && rm -f /etc/systemd/system/multi-user.target.wants/dnsmasq.service \
 && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
