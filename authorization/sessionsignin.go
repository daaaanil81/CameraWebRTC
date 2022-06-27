package authorization

import (
	"camera/authorization/identity"
	"camera/sessions"
	"fmt"
	"net/http"
)

const (
	ServiceUserKey     = "service_user"
	UKNOWN_USER    int = -1
)

type SessionSignInMgr struct {
	Request *http.Request
	Writer  http.ResponseWriter
}

func (mgr *SessionSignInMgr) SignIn(user identity.User) (err error) {
	session, err := mgr.getSession()
	if err == nil {
		session.SetValue(ServiceUserKey, user.GetID())
		session.Save(mgr.Request, mgr.Writer)
	}
	return
}

func (mgr *SessionSignInMgr) SignOut(user identity.User) (err error) {
	session, err := mgr.getSession()
	if err == nil {
		session.SetValue(ServiceUserKey, nil)
		session.Save(mgr.Request, mgr.Writer)
	}
	return
}

func (mgr *SessionSignInMgr) Check() (id int, err error) {
	session, err := mgr.getSession()
	if err == nil {
		id = session.GetValueDefault(ServiceUserKey, UKNOWN_USER).(int)
	}
	return
}

func (mgr *SessionSignInMgr) getSession() (s sessions.Session, err error) {
	if c := mgr.Request.Context().Value(sessions.ServiceSessionKey); c != nil {
		s = c.(sessions.Session)
	} else {
		err = fmt.Errorf("Don't find Session key")
	}
	return
}
