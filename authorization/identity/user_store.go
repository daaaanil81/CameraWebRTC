package identity

const ServiceUserStoreKey = "service_user_store"

type UserStore interface {
	GetUserByID(id int) (user User, found bool)
	GetUserByName(name string) (user User, found bool)
}
