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

RUN wget https://go.dev/dl/go1.17.9.linux-amd64.tar.gz && \
    echo "9dacf782028fdfc79120576c872dee488b81257b1c48e9032d122cfdb379cca6 go1.17.9.linux-amd64.tar.gz" | sha256sum -c && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.9.linux-amd64.tar.gz
ENV PATH /usr/local/go/bin:$PATH

RUN go version

RUN groupadd --gid $GID --non-unique buildboy
RUN useradd buildboy --create-home --shell /bin/bash --non-unique --uid $UID --gid $GID
USER buildboy
WORKDIR /home/buildboy
RUN mkdir go
ENV GOPATH /home/buildboy/go

ENV PATH $GOPATH/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH
