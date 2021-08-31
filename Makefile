mainprogram=camera_daemon
build_commit=$(shell git rev-parse HEAD)
build_version=$(shell git describe --tags 2> /dev/null || echo "dev-$(shell git rev-parse HEAD)")

.PHONY: version
version:
	echo $(build_version)
	echo $(build_commit)

.PHONY: build
build:
	@go build -v \
		-o $(mainprogram) cmd/project/*.go

.PHONY: run
run:
	make build
	@./$(mainprogram)

clean:
