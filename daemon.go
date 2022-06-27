package main

import (
	"camera/http"
	"camera/services"
)

var JSON_FILE = "config.json"

func main() {
	services.NewServiceContext(JSON_FILE)
	wg := http.Server()
	wg.Wait()
}
