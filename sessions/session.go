package sessions

import (
	"net/http"

	gorilla "github.com/gorilla/sessions"
)

type Session interface {
	GetValue(key string) interface{}
	GetValueDefault(key string, defVal interface{}) interface{}
	SetValue(key string, val interface{})
	Save(request *http.Request, writer http.ResponseWriter)
}

type SessionAdaptor struct {
	gSession *gorilla.Session
}

func (adaptor *SessionAdaptor) GetValue(key string) interface{} {
	return adaptor.gSession.Values[key]
}

func (adaptor *SessionAdaptor) GetValueDefault(key string,
	defVal interface{}) interface{} {

	if val, ok := adaptor.gSession.Values[key]; ok {
		return val
	}
	return defVal
}

func (adaptor *SessionAdaptor) SetValue(key string, val interface{}) {
	if val == nil {
		adaptor.gSession.Values[key] = nil
	} else {
		switch typeVal := val.(type) {
		case int, float64, bool, string:
			adaptor.gSession.Values[key] = typeVal
		default:
			panic("Session only support int, float64, bool and string values")
		}
	}
}

func CreateSessionAdaptor(session *gorilla.Session) Session {
	return &SessionAdaptor{session}
}

func (adaptor *SessionAdaptor) Save(request *http.Request, writer http.ResponseWriter) {
	adaptor.gSession.Save(request, writer)
}
