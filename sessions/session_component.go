package sessions

import (
	"camera/config"
	"crypto/md5"
	"io"
	"net/http"
	"time"

	gorilla "github.com/gorilla/sessions"
)

type SessionComponent struct {
	store *gorilla.CookieStore
}

func (s *SessionComponent) Get(request *http.Request,
	name string) (*gorilla.Session, error) {

	return s.store.Get(request, name)
}

func CreateSessionComponent(cfg config.Configuration) (component SessionComponent) {
	hash := md5.New()

	if key, ok := cfg.GetString("sessions:key"); ok {
		io.WriteString(hash, key)
	} else {
		panic("Session key wasn't found")
	}

	if cfg.GetBoolDefault("session:cyclekey", true) {
		io.WriteString(hash, time.Now().String())
	}

	component.store = gorilla.NewCookieStore(hash.Sum(nil))

	return
}
