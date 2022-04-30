package http

import (
	"camera/config"
	"camera/logging"
	"camera/services"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

type serverAdaptor struct {
	config.Configuration
	logging.Logger
}

func (adaptor serverAdaptor) GetRequest(writer http.ResponseWriter,
	request *http.Request) {

	first := strings.Index(request.URL.RequestURI()[1:], "/") + 2

	path := request.URL.RequestURI()[:first]
	switch path {
	case "/":
		adaptor.GetIndexTemplate(writer, request)
	}
}

func (adaptor serverAdaptor) PostRequest(writer http.ResponseWriter,
	request *http.Request) {

}

func (adaptor serverAdaptor) ServeHTTP(writer http.ResponseWriter,
	request *http.Request) {

	adaptor.Tracef("REQ --- %v - %v", request.Method, request.URL.String())

	switch request.Method {
	case http.MethodGet:
		adaptor.GetRequest(writer, request)
	case http.MethodPost:
		adaptor.PostRequest(writer, request)
	default:
		adaptor.Warnf("Request wasn't processed")
	}
}

func Server() *sync.WaitGroup {
	wg := sync.WaitGroup{}
	var cfg config.Configuration
	var logger logging.Logger

	services.GetService(&cfg)
	services.GetService(&logger)

	adaptor := serverAdaptor{cfg, logger}

	enableHttp := adaptor.GetBoolDefault("http:enableHttp", true)
	if enableHttp {
		httpPort := adaptor.GetIntDefault("http:port", 8888)
		adaptor.Debugf("Starting HTTP server on port %v", httpPort)
		wg.Add(1)
		go func() {
			err := http.ListenAndServe(fmt.Sprintf(":%v", httpPort), adaptor)
			if err != nil {
				panic(err)
			}
		}()
	}

	enableHttps := adaptor.GetBoolDefault("https:enableHttps", false)
	if enableHttps {
		httpsPort := adaptor.GetIntDefault("https:port", 9999)
		certFile, cfok := adaptor.GetString("https:certFile")
		keyFile, kfok := adaptor.GetString("https:keyFile")
		if cfok && kfok {
			adaptor.Debugf("Starting HTTPS server on port %v", httpsPort)
			wg.Add(1)
			go func() {
				err := http.ListenAndServeTLS(fmt.Sprintf(":%v", httpsPort),
					certFile, keyFile, adaptor)
				if err != nil {
					panic(err)
				}
			}()
		} else {
			panic("Don't find cert or key files")
		}
	}
	return &wg
}
