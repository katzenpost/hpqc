PODMAN ?= podman
DISTRO ?= debian-13
DEB_DISTROS ?= debian-13 debian-forky ubuntu-24.04 ubuntu-26.04
DEB_IMAGE = packaging/container/deb-image.sh

.PHONY: deb deb-build deb-ci deb-test deb-image-ref deb-image \
	deb-image-push deb-image-refs

deb: deb-image
	@$(PODMAN) run --rm -v "$(CURDIR)":/build:z -w /build \
		"$$($(DEB_IMAGE) --ref $(DISTRO))" make deb-build

deb-build:
	@packaging/debian/build.sh

deb-ci:
	@packaging/debian/ci.sh

deb-test:
	@packaging/debian/test.sh

deb-image-ref:
	@$(DEB_IMAGE) --ref $(DISTRO)

deb-image-refs:
	@for d in $(DEB_DISTROS); do \
		key=$$(printf '%s' "$$d" | tr '.-' '__'); \
		printf 'ref_%s=%s\n' "$$key" "$$($(DEB_IMAGE) --ref $$d)"; \
	done

deb-image:
	@$(DEB_IMAGE) --ensure $(DISTRO)

deb-image-push:
	@$(DEB_IMAGE) --push $(DISTRO)
