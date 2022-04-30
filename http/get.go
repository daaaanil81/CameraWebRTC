package http

import (
	"html/template"
	"net/http"
	"os"
)

func (adaptor serverAdaptor) GetIndexTemplate(writer http.ResponseWriter,
	request *http.Request) {

	adaptor.Infof("Connection: %v", request.RemoteAddr)

	templates, err := template.ParseFiles("static/index.html", "static/form.html")
	if err == nil {
		selectedTemp := templates.Lookup("mainTemplate")
		err = selectedTemp.Execute(writer, nil)
		if err != nil {
			adaptor.Warn(err.Error())
		}
	} else {
		adaptor.Warn(err.Error())
	}
}

func (adaptor serverAdaptor) GetFiles(writer http.ResponseWriter,
	request *http.Request, fileName string) {

	data, err := os.ReadFile("static/" + fileName)
	if err != nil {
		http.NotFound(writer, request)
	} else {
		writer.Write(data)
	}
}
