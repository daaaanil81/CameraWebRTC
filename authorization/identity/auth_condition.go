package identity

const ServiceRolesKey = "service_roles"

type AuthorizationCondition interface {
	Validate(user User) Level
}
