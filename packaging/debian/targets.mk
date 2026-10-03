.PHONY: deb deb-ci deb-test

deb:
	@packaging/debian/build.sh

deb-ci:
	@packaging/debian/ci.sh

deb-test:
	@packaging/debian/test.sh
