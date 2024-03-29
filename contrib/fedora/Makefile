.PHONY: srpm

.SHELLFLAGS := -xc

spec_dir := $(shell rpm --eval "%{_specdir}")
source_dir := $(shell rpm --eval "%{_sourcedir}")
srcrpm_dir := $(shell rpm --eval "%{_srcrpmdir}")

our_version := `git describe --tags | cut -d'-' -f1`
our_release := `git describe --tags | cut -s -d'-' -f2- | tr '-' '_'`

project_name := fred-cdnskey-scanner
spec_file := $(project_name).spec

srpm:
	rpm -q git > /dev/null 2>&1 || dnf -y install git
	mkdir -p "$(source_dir)" && \
	mkdir -p "$(spec_dir)" && \
	./dependencies.sh -r && \
	our_version=$(our_version); \
	tar -cf "$(source_dir)/.getdns.tar" --transform "s!3rd_party/getdns!$(project_name)-$(our_version)/3rd_party/getdns!"  3rd_party/getdns
	git archive --prefix=$(project_name)-$(our_version)/ --format=tar HEAD -o "$(source_dir)/$(project_name)-$(our_version).tar" &&  \
	tar --concatenate --file="$(source_dir)/$(project_name)-$(our_version).tar" "$(source_dir)/.getdns.tar" && \
	gzip -f "$(source_dir)/$(project_name)-$(our_version).tar"
	echo "%define our_version $(our_version)" > $(spec_dir)/$(spec_file) && \
	if [[ -n "$(our_release)" ]]; then echo "%define our_release $(our_release)" >> $(spec_dir)/$(spec_file); fi && \
	cat .copr/$(spec_file) >> $(spec_dir)/$(spec_file) && \
	rpmbuild -bs $(spec_dir)/$(spec_file) && \
	mv $(srcrpm_dir)/$(project_name)*.src.rpm $(outdir)
