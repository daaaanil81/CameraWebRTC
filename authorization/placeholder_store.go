package authorization

import (
	"camera/authorization/identity"
	"encoding/json"
	"os"
	"strings"
)

var users map[int]identity.User

func init() {
	var usersJson identity.UserJsonList

	data, err := os.ReadFile("users.json")
	if err == nil {
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		err = decoder.Decode(&usersJson)
		if err != nil {
			panic(err.Error())
		}

		users = make(map[int]identity.User, usersJson.GetLen())
		usersJson.GetUsers(users)

	} else {
		panic(err.Error())
	}
}

type PlaceholderUserStore struct{}

func NewUserStore() identity.UserStore {
	return &PlaceholderUserStore{}
}

func (store *PlaceholderUserStore) GetUserByID(id int) (identity.User, bool) {
	user, found := users[id]
	return user, found
}

func (store *PlaceholderUserStore) GetUserByName(name string) (identity.User,
	bool) {

	for _, user := range users {
		if strings.EqualFold(user.GetDisplayName(), name) {
			return user, true
		}
	}
	return nil, false
}
