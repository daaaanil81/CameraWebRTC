package identity

import (
	"encoding/json"
	"strings"
)

var UnauthenticatedUser User = &basicUser{}

type Level int

const (
	UNKNOWN_LEVEL Level = iota
	LOW_LEVEL
	HIGH_LEVEL
)

func NewBasicUser(id int, name string, password string, role string) User {
	return &basicUser{
		UserJson: &UserJson{Id: id,
			Username: name,
			Password: password,
			Role:     role},
		Authenticated: true,
	}
}

type UserJson struct {
	Id       int
	Username string
	Password string
	Role     string
}

type UserJsonList struct {
	users []UserJson
}

func (usersJson *UserJsonList) UnmarshalJSON(data []byte) (err error) {
	mdata := map[string]interface{}{}
	err = json.Unmarshal(data, &mdata)

	if err == nil {
		if users_map, ok := mdata["users"].([]interface{}); ok {
			usersJson.users = make([]UserJson, len(users_map))
			for i, elem_map := range users_map {
				empty_map := elem_map.(map[string]interface{})
				user_map := empty_map["user"].(map[string]interface{})
				if id, ok := user_map["Id"].(int); ok {
					usersJson.users[i].Id = id
				}
				if username, ok := user_map["Username"].(string); ok {
					usersJson.users[i].Username = username
				}
				if password, ok := user_map["Password"].(string); ok {
					usersJson.users[i].Password = password
				}
				if role, ok := user_map["Role"].(string); ok {
					usersJson.users[i].Role = role
				}
			}
		}
	}

	return
}

func (usersJson *UserJsonList) GetLen() int {
	return len(usersJson.users)
}

func (usersJson *UserJsonList) GetUsers(users map[int]User) {
	for _, user := range usersJson.users {
		users[user.Id] = NewBasicUser(user.Id, user.Username, user.Password, user.Role)
	}
}

type basicUser struct {
	*UserJson
	Authenticated bool
}

func (user *basicUser) GetID() int {
	return user.Id
}

func (user *basicUser) GetDisplayName() string {
	return user.Username
}

func (user *basicUser) GetPassword() string {
	return user.Password
}

func (user *basicUser) InRole(role string) bool {
	return strings.EqualFold(user.Role, role)
}

func (user *basicUser) IsAuthenticated() bool {
	return user.Authenticated
}
