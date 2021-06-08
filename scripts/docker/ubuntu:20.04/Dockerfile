FROM ubuntu:20.04
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update                       \
        && apt-get -y install               \
            cmake                           \
            pkg-config                      \
            build-essential                 \
            ninja-build                     \
            bash-completion                 \
            git                             \
            libboost-system-dev             \
            libevent-dev                    \
            libgetdns-dev                   \
        && apt-get -y clean                 \
        && rm -rf /var/lib/apt/lists/*
