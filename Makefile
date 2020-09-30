.PHONY: builder builder_image install clean

all: hercules mockules

install: all
ifndef DESTDIR
	$(error DESTDIR is not set)
endif
	cp hercules mockules/mockules $(DESTDIR)

hercules: builder hercules.h hercules.go hercules.c bpf_prgm/redirect_userspace.o bpf_prgm/pass.o
	@# update modification dates in assembly, so that the new version gets loaded
	@sed -i -e "s/\(load bpf_prgm_pass\)\( \)\?\([0-9a-f]\{32\}\)\?/\1 $$(md5sum bpf_prgm/pass.c | head -c 32)/g" bpf_prgms.s
	@sed -i -e "s/\(load bpf_prgm_redirect_userspace\)\( \)\?\([0-9a-f]\{32\}\)\?/\1 $$(md5sum bpf_prgm/redirect_userspace.c | head -c 32)/g" bpf_prgms.s
	@taggedRef=$$(git describe --tags --long --dirty 2>/dev/null) && startupVersion=$$(git rev-parse --abbrev-ref HEAD)"-$${taggedRef}" || \
		startupVersion=$$(git rev-parse --abbrev-ref HEAD)"-untagged-"$$(git describe --tags --dirty --always); \
	docker exec hercules-builder go build -ldflags "-X main.startupVersion=$${startupVersion}"

bpf_prgm/%.ll: bpf_prgm/%.c builder
	docker exec hercules-builder clang -S -target bpf -D __BPF_TRACING__ -I. -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o $@ $<

bpf_prgm/redirect_userspace.o: bpf_prgm/redirect_userspace.ll builder
	docker exec hercules-builder llc -march=bpf -filetype=obj -o $@ $<

bpf_prgm/pass.o: bpf_prgm/pass.ll builder
	docker exec hercules-builder llc -march=bpf -filetype=obj -o $@ $<

#bpf_prgm/redirect_userspace.ll: bpf_prgm/redirect_userspace.c builder
#	docker exec hercules-builder clang -S -target bpf -D __BPF_TRACING__ -I. -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o $@ $<

#bpf_prgm/pass.ll: bpf_prgm/pass.c builder
#	docker exec hercules-builder clang -S -target bpf -D __BPF_TRACING__ -I. -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o $@ $<

#bpf_prgm/redirect_userspace.o: bpf_prgm_redirect_userspace.ll builder
#	docker exec hercules-builder llc -march=bpf -filetype=obj -o $@ $<

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
