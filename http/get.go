package http

import (
	"html/template"
	"net/http"
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
