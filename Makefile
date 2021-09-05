BIN           := camera_daemon
BIN_DIR       := bin
BIN_PATH      := $(BIN_DIR)/$(BIN)
SOURCE_DIR    := src
BUILD_COMMIT  := $(shell git rev-parse HEAD)
BUILD_VERSION := $(shell git describe --tags 2> /dev/null || echo "dev-$(shell git rev-parse HEAD)")

.PHONY: build
build:
	mkdir -p $(BIN_DIR)
	@go build -o $(BIN_PATH) $(SOURCE_DIR)/*.go

.PHONY: version
version:
	echo $(BUILD_VERSION)
	echo $(BUILD_COMMIT)

.PHONY: run
run:
	make build
	@./$(BIN_PATH)

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
