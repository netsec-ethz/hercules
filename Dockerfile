# ubuntu/focal with go-1.21.6
# copy pasted from
# https://github.com/docker-library/golang/blob/master/1.21/bullseye/Dockerfile
# but with a different base image (ubuntu:focal instead of debian:bullseye)

FROM ubuntu:focal
ARG UID=1001
ARG GID=1001

# install cgo-related dependencies
RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
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
	; \
	rm -rf /var/lib/apt/lists/*

ENV PATH /usr/local/go/bin:$PATH

ENV GOLANG_VERSION 1.21.6

RUN set -eux; \
	arch="$(dpkg --print-architecture)"; arch="${arch##*-}"; \
	url=; \
	case "$arch" in \
		'amd64') \
			url='https://dl.google.com/go/go1.21.6.linux-amd64.tar.gz'; \
			sha256='3f934f40ac360b9c01f616a9aa1796d227d8b0328bf64cb045c7b8c4ee9caea4'; \
			;; \
		'armhf') \
			url='https://dl.google.com/go/go1.21.6.linux-armv6l.tar.gz'; \
			sha256='6a8eda6cc6a799ff25e74ce0c13fdc1a76c0983a0bb07c789a2a3454bf6ec9b2'; \
			;; \
		'arm64') \
			url='https://dl.google.com/go/go1.21.6.linux-arm64.tar.gz'; \
			sha256='e2e8aa88e1b5170a0d495d7d9c766af2b2b6c6925a8f8956d834ad6b4cacbd9a'; \
			;; \
		'i386') \
			url='https://dl.google.com/go/go1.21.6.linux-386.tar.gz'; \
			sha256='05d09041b5a1193c14e4b2db3f7fcc649b236c567f5eb93305c537851b72dd95'; \
			;; \
		'mips64el') \
			url='https://dl.google.com/go/go1.21.6.linux-mips64le.tar.gz'; \
			sha256='eb309a611dfec52b98805e05bafbe769d3d5966aef05f17ec617c89ee5a9e484'; \
			;; \
		'ppc64el') \
			url='https://dl.google.com/go/go1.21.6.linux-ppc64le.tar.gz'; \
			sha256='e872b1e9a3f2f08fd4554615a32ca9123a4ba877ab6d19d36abc3424f86bc07f'; \
			;; \
		'riscv64') \
			url='https://dl.google.com/go/go1.21.6.linux-riscv64.tar.gz'; \
			sha256='86a2fe6597af4b37d98bca632f109034b624786a8d9c1504d340661355ed31f7'; \
			;; \
		's390x') \
			url='https://dl.google.com/go/go1.21.6.linux-s390x.tar.gz'; \
			sha256='92894d0f732d3379bc414ffdd617eaadad47e1d72610e10d69a1156db03fc052'; \
			;; \
		*) echo >&2 "error: unsupported architecture '$arch' (likely packaging update needed)"; exit 1 ;; \
	esac; \
	\
	wget -O go.tgz.asc "$url.asc"; \
	wget -O go.tgz "$url" --progress=dot:giga; \
	echo "$sha256 *go.tgz" | sha256sum -c -; \
	\
# https://github.com/golang/go/issues/14739#issuecomment-324767697
	GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \
# https://www.google.com/linuxrepositories/
	gpg --batch --keyserver keyserver.ubuntu.com --recv-keys 'EB4C 1BFD 4F04 2F6D DDCC  EC91 7721 F63B D38B 4796'; \
# let's also fetch the specific subkey of that key explicitly that we expect "go.tgz.asc" to be signed by, just to make sure we definitely have it
	gpg --batch --keyserver keyserver.ubuntu.com --recv-keys '2F52 8D36 D67B 69ED F998  D857 78BD 6547 3CB3 BD13'; \
	gpg --batch --verify go.tgz.asc go.tgz; \
	gpgconf --kill all; \
	rm -rf "$GNUPGHOME" go.tgz.asc; \
	\
	tar -C /usr/local -xzf go.tgz; \
	rm go.tgz; \
	\
	go version

# don't auto-upgrade the gotoolchain
# https://github.com/docker-library/golang/issues/472
ENV GOTOOLCHAIN=local

RUN groupadd --gid $GID --non-unique buildboy
RUN useradd buildboy --create-home --shell /bin/bash --non-unique --uid $UID --gid $GID
USER buildboy
WORKDIR /home/buildboy
RUN mkdir go
ENV GOPATH /home/buildboy/go
ENV PATH $GOPATH/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH
