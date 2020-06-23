.PHONY: builder builder_image install clean

all: hercules mockules

install: all
ifndef DESTDIR
	$(error DESTDIR is not set)
endif
	cp hercules mockules/mockules $(DESTDIR)

hercules: builder hercules.h hercules.go hercules.c
	@taggedRef=$$(git describe --tags --long --dirty 2>/dev/null) && startupVersion=$$(git rev-parse --abbrev-ref HEAD)"-$${taggedRef}" || \
		startupVersion=$$(git rev-parse --abbrev-ref HEAD)"-untagged-"$$(git describe --tags --dirty --always); \
	docker exec hercules-builder go build -ldflags "-X main.startupVersion=$${startupVersion}"

mockules: builder mockules/main.go
	docker exec -w /`basename $(PWD)`/mockules hercules-builder go build

builder: builder_image
	@docker container ls -a --format={{.Names}} | grep hercules-builder -q || \
		docker run -t --entrypoint cat --name hercules-builder -v $(PWD):/`basename $(PWD)` -w /`basename $(PWD)` -d hercules-builder
	@docker container ls --format={{.Names}} | grep hercules-builder -q || \
		docker start hercules-builder

builder_image:
	@docker images | grep hercules-builder -q || \
		docker build -t hercules-builder .

clean:
	rm -f hercules mockules/mockules
	docker container rm -f hercules-builder || true
	docker rmi hercules-builder || true
