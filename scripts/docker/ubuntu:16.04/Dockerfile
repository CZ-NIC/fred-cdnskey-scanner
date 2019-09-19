FROM ubuntu:16.04
ENV DEBIAN_FRONTEND noninteractive

RUN printf 'deb http://archive.nic.cz/ubuntu xenial main\n' > /etc/apt/sources.list.d/cz.nic.list \
        && apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 1C0200016A9AC5C6

RUN apt-get -y update                       \
        && apt-get -y install               \
            cmake                           \
            pkg-config                      \
            build-essential                 \
            ninja-build                     \
            bash-completion                 \
            git                             \
            libboost-system-dev             \
            libgetdns-dev                   \
            libevent-dev                    \
            libevent-2.0                    \
        && apt-get -y clean                 \
        && rm -rf /var/lib/apt/lists/*
