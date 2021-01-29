FROM fedora:33

RUN dnf -y install            \
        git                   \
        gcc-c++               \
        make                  \
        cmake                 \
        getdns-devel          \
        libevent-devel        \
        boost-devel           \
        boost-system          \
    && dnf clean all          \
    && rm -rf /var/cache/yum
