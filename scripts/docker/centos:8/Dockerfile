FROM centos:8

RUN dnf -y install            \
        git                   \
        cmake                 \
        libarchive            \
        make                  \
        gcc-c++               \
        libevent-devel        \
        boost-devel           \
        boost-system          \
        openssl-devel         \
        libidn2-devel         \
        unbound-devel         \
        check-devel           \
    && dnf clean all          \
    && rm -rf /var/cache/yum
