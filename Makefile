########################################################################
##
## Copyright (C) 2017  CZ.NIC, z.s.p.o.
##
## This file is part of FRED.
##
## FRED is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, version 2 of the License.
##
## FRED is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with FRED.  If not, see <http://www.gnu.org/licenses/>.
##
########################################################################

.PHONY: all clean test

SRC_DIR = src
BUILD_DIR = build
EVENT_DIR := $(BUILD_DIR)/event
GETDNS_DIR := $(BUILD_DIR)/getdns
BINARY = $(BUILD_DIR)/cdnskey-scanner
OBJS := $(BUILD_DIR)/main.o $(EVENT_DIR)/base.o $(GETDNS_DIR)/error.o $(GETDNS_DIR)/data.o \
$(GETDNS_DIR)/context.o $(GETDNS_DIR)/extensions.o $(GETDNS_DIR)/rrtype.o $(GETDNS_DIR)/solver.o
DBG_OPT = -ggdb3
WARN_OPT = -W -Wall
CFLAGS := -I. $(DBG_OPT) $(WARN_OPT) -O0

all: $(BINARY)

# pull in dependency info for *existing* .o files
-include $(OBJS:.o=.d)

$(BINARY): $(OBJS)
	$(CXX) $(DBG_OPT) $^ -o $@ -lgetdns -lgetdns_ext_event -levent -lboost_system

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cc
	@$(MAKE) --no-print-directory -s $(BUILD_DIR) $(EVENT_DIR) $(GETDNS_DIR)
	$(CXX) $(CFLAGS) -o $@ -c $(filter %.cc,$^)
	@$(CXX) -MM $(CFLAGS) $(SRC_DIR)/$*.cc | sed "s,^.*:,$@:," > $(@:.o=.d)
	@cp $(@:.o=.d) $(@:.o=.d.tmp)
	@sed -e 's/.*://' -e 's/\\$$//' < $(@:.o=.d.tmp) | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $(@:.o=.d)
	@rm -f $(@:.o=.d.tmp)

$(BUILD_DIR) $(EVENT_DIR) $(GETDNS_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)

test: $(BINARY)
	@$(BINARY) 1 \
--hostname_resolvers "127.0.1.1" \
--cdnskey_resolvers "172.16.1.183" \
--dnssec_trust_anchors ". 257 3 8 \
AwEAAdAjHYjqJ6ovPqU+mVFrrvIaqPiQfmNRbv4LX/A0xqcgL\
ZjVC4Mw1bNgU+yvE4J3ICiYk2nKRdYY+9OmKdkb1o7Pl6K7uC\
q2PiIBFOtj610B+eS7xvhOp9JnXXKcCg/tgkMCAPZ89RczNmQ\
BJtFzjgytjNPNgl2a2ApOKXOVE5xFL6YcWW0p8rPdCnNE2HUQ\
wIJTnxkWf/cLY4gY21TWKIfsE024qXE+8jxbHIFpDzAG5VrnN\
E0yS2p24ad45IlhHHJI1K076lKOAXRpv7S7HE0JbTx3SxFcNr\
wRdX3WM/pkFxgBzrTk1bpcWWUbLX3mb5nZPv9v0RQ4qYoo11a\
xAU8=" < test/data.txt