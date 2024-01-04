# ubuntu/disco with go-1.15
# copy pasted from 
#  https://github.com/docker-library/golang/blob/master/1.15/buster/Dockerfile
# but with a different base image (ubuntu:disco instead of debian:stretch); we
# need the newer kernel headers to build XDP C code against

FROM ubuntu:focal
ARG UID=1001
ARG GID=1001

# gcc for cgo
RUN apt-get update && apt-get install -y --no-install-recommends \
		g++ \
		gcc \
		libc6-dev \
		make \
		pkg-config \
		wget \
		git \
		apt-transport-https \
		ca-certificates \
		libelf-dev \
		vim less \
		gpg \
		gpg-agent \
		dirmngr \
		clang \
		llvm \
		libelf-dev \
		libpcap-dev \
		gcc-multilib \
		build-essential \
	&& rm -rf /var/lib/apt/lists/*

ENV PATH /usr/local/go/bin:$PATH

ENV GOLANG_VERSION 1.15

RUN set -eux; \
	\
	dpkgArch="$(dpkg --print-architecture)"; \
	case "${dpkgArch##*-}" in \
		'amd64') \
			arch='linux-amd64'; \
			url='https://storage.googleapis.com/golang/go1.15.linux-amd64.tar.gz'; \
			sha256='2d75848ac606061efe52a8068d0e647b35ce487a15bb52272c427df485193602'; \
			;; \
		'armhf') \
			arch='linux-armv6l'; \
			url='https://storage.googleapis.com/golang/go1.15.linux-armv6l.tar.gz'; \
			sha256='6d8914ddd25f85f2377c269ccfb359acf53adf71a42cdbf53434a7c76fa7a9bd'; \
			;; \
		'arm64') \
			arch='linux-arm64'; \
			url='https://storage.googleapis.com/golang/go1.15.linux-arm64.tar.gz'; \
			sha256='7e18d92f61ddf480a4f9a57db09389ae7b9dadf68470d0cb9c00d734a0c57f8d'; \
			;; \
		'i386') \
			arch='linux-386'; \
			url='https://storage.googleapis.com/golang/go1.15.linux-386.tar.gz'; \
			sha256='68ce979083126694ceef60233f69efe870f54af24d81a120f76265107a9e9aab'; \
			;; \
		'ppc64el') \
			arch='linux-ppc64le'; \
			url='https://storage.googleapis.com/golang/go1.15.linux-ppc64le.tar.gz'; \
			sha256='4603736a158b3d8ac52b9245f39bf715936c801e05bb5ad7c44b1edd6d5ef6a2'; \
			;; \
		's390x') \
			arch='linux-s390x'; \
			url='https://storage.googleapis.com/golang/go1.15.linux-s390x.tar.gz'; \
			sha256='8825f93caaf87465e32f298408c48b98d4180f3ddb885bd027f2926e711d23e8'; \
			;; \
		*) \
# https://github.com/golang/go/issues/38536#issuecomment-616897960
			arch='src'; \
			url='https://storage.googleapis.com/golang/go1.15.src.tar.gz'; \
			sha256='69438f7ed4f532154ffaf878f3dfd83747e7a00b70b3556eddabf7aaee28ac3a'; \
			echo >&2; \
			echo >&2 "warning: current architecture ($dpkgArch) does not have a corresponding Go binary release; will be building from source"; \
			echo >&2; \
			;; \
	esac; \
	\
	wget -O go.tgz.asc "$url.asc" --progress=dot:giga; \
	wget -O go.tgz "$url" --progress=dot:giga; \
	echo "$sha256 *go.tgz" | sha256sum --strict --check -; \
	\
# https://github.com/golang/go/issues/14739#issuecomment-324767697
	export GNUPGHOME="$(mktemp -d)"; \
# https://www.google.com/linuxrepositories/
	gpg --batch --keyserver hkps://keyserver.ubuntu.com:443 --recv-keys 'EB4C 1BFD 4F04 2F6D DDCC EC91 7721 F63B D38B 4796'; \
	gpg --batch --verify go.tgz.asc go.tgz; \
	rm -rf "$GNUPGHOME" go.tgz.asc; \
	\
	tar -C /usr/local -xzf go.tgz; \
	rm go.tgz; \
	\
	if [ "$arch" = 'src' ]; then \
		savedAptMark="$(apt-mark showmanual)"; \
		apt-get update; \
		apt-get install -y --no-install-recommends golang-go; \
		\
		goEnv="$(go env | sed -rn -e '/^GO(OS|ARCH|ARM|386)=/s//export \0/p')"; \
		eval "$goEnv"; \
		[ -n "$GOOS" ]; \
		[ -n "$GOARCH" ]; \
		( \
			cd /usr/local/go/src; \
			./make.bash; \
		); \
		\
		apt-mark auto '.*' > /dev/null; \
		apt-mark manual $savedAptMark > /dev/null; \
		apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
		rm -rf /var/lib/apt/lists/*; \
		\
# pre-compile the standard library, just like the official binary release tarballs do
		go install std; \
# go install: -race is only supported on linux/amd64, linux/ppc64le, linux/arm64, freebsd/amd64, netbsd/amd64, darwin/amd64 and windows/amd64
#		go install -race std; \
		\
# remove a few intermediate / bootstrapping files the official binary release tarballs do not contain
		rm -rf \
			/usr/local/go/pkg/*/cmd \
			/usr/local/go/pkg/bootstrap \
			/usr/local/go/pkg/obj \
			/usr/local/go/pkg/tool/*/api \
			/usr/local/go/pkg/tool/*/go_bootstrap \
			/usr/local/go/src/cmd/dist/dist \
		; \
	fi; \
	\
	go version

RUN groupadd --gid $GID --non-unique buildboy
RUN useradd buildboy --create-home --shell /bin/bash --non-unique --uid $UID --gid $GID
USER buildboy
WORKDIR /home/buildboy
RUN mkdir go
ENV GOPATH /home/buildboy/go

ENV PATH $GOPATH/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH
