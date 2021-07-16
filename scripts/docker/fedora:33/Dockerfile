FROM fedora:33

RUN dnf -y install            \
        git                   \
        gcc-c++               \
        make                  \
        cmake                 \
        libevent-devel        \
        boost-devel           \
        boost-system          \
        openssl-devel         \
        libidn2-devel         \
        unbound-devel         \
        check-devel           \
    && dnf clean all          \
    && rm -rf /var/cache/yum
