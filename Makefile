BUILD_IMAGE := ryarnyah/docker-golang-builder:latest
RELEASE_IMAGE := ryarnyah/docker-github-release:latest
GITHUB_USER := ryarnyah
GITHUB_REPO := local-dns-proxy
GIT_TAG := v1.0.0

PLATFORMS := linux/arm linux/amd64 windows/amd64

all: $(PLATFORMS)

temp = $(subst /, ,$@)
os = $(word 1, $(temp))
arch = $(word 2, $(temp))

$(PLATFORMS):
	docker run --rm -e GOOS=${os} -e GOARCH=${arch} -v ${PWD}:/go/src/github.com/$(GITHUB_USER)/${GITHUB_REPO} -w /go/src/github.com/${GITHUB_USER}/${GITHUB_REPO} ${BUILD_IMAGE}

release: $(PLATFORMS)
	@- $(foreach XYZ,$^, \
			  $(eval temp = $(subst /, ,${XYZ})) \
				$(eval os = $(word 1, $(temp))) \
				$(eval arch = $(word 2, $(temp))) \
        \
        $(shell docker run --rm -e GITHUB_USER=${GITHUB_USER} -e GITHUB_REPO=${GITHUB_REPO} -e GIT_TAG=${GIT_TAG} -e BINARY_NAME=${GITHUB_REPO}-${os}-${arch} -e GITHUB_TOKEN=${GITHUB_TOKEN} -v ${PWD}:/go/src/github.com/${GITHUB_USER}/${GITHUB_REPO} -w /go/src/github.com/${GITHUB_USER}/${GITHUB_REPO} ${RELEASE_IMAGE}) \
    )

clean:
	rm -f ${GITHUB_REPO}-*

.PHONY: all $(PLATFORMS) release
