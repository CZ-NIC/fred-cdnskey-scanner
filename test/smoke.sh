testdir="$(dirname $0)"
binary=$1

${binary} 5 \
--hostname_resolvers "172.20.20.253" \
--cdnskey_resolvers "172.16.1.183" \
--dnssec_trust_anchors ". 257 3 8 \
AwEAAdAjHYjqJ6ovPqU+mVFrrvIaqPiQfmNRbv4LX/A0xqcgL\
ZjVC4Mw1bNgU+yvE4J3ICiYk2nKRdYY+9OmKdkb1o7Pl6K7uC\
q2PiIBFOtj610B+eS7xvhOp9JnXXKcCg/tgkMCAPZ89RczNmQ\
BJtFzjgytjNPNgl2a2ApOKXOVE5xFL6YcWW0p8rPdCnNE2HUQ\
wIJTnxkWf/cLY4gY21TWKIfsE024qXE+8jxbHIFpDzAG5VrnN\
E0yS2p24ad45IlhHHJI1K076lKOAXRpv7S7HE0JbTx3SxFcNr\
wRdX3WM/pkFxgBzrTk1bpcWWUbLX3mb5nZPv9v0RQ4qYoo11a\
xAU8=" < ${testdir}/data.txt
