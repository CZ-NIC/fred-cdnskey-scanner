FROM fedora:30
RUN dnf -y clean all                  \
        && dnf -y update              \
        && dnf -y install             \
                git                   \
                gcc-c++               \
                make                  \
                cmake                 \
                getdns-devel          \
                libevent-devel        \
                boost-devel           \
                boost-system
