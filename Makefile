BIN           := camera
SOURCE_DIR    := camera_daemon
BIN_PATH      := $(SOURCE_DIR)/$(BIN)
BUILD_COMMIT  := $(shell git rev-parse HEAD)
BUILD_VERSION := $(shell git describe --tags 2> /dev/null || echo "dev-$(shell git rev-parse HEAD)")

.PHONY: build
build:
	@go build -o $(BIN_PATH) $(SOURCE_DIR)/*.go

.PHONY: version
version:
	echo $(BUILD_VERSION)
	echo $(BUILD_COMMIT)

.PHONY: run
run:
	make build
	@./$(BIN_PATH)


.PHONY: install
install:
	mkdir -p /etc/camera_server
	cp -r $(SOURCE_DIR)/static /etc/camera_server/
##	sudo cp $(SOURCE_DIR)/static/certificate/danil_petrov.crt /usr/local/share/ca-certificates/
##	sudo cp $(SOURCE_DIR)/static/certificate/danil_petrov.key /usr/local/share/ca-certificates/
##	sudo update-ca-certificates --fresh

.PHONY: clean
clean:
	rm -rf /etc/camera_server/
	rm -rf $(BIN_PATH)
