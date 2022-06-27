package authorization

import (
	"camera/authorization/identity"
	"camera/config"
)

func NewRoleCondition(cfg config.Configuration) identity.AuthorizationCondition {
	var roles []string

	value, found := cfg.GetStringSlice("users:roles")
	if found {
		roles = value
	} else {
		roles = []string{"Administrator"}
	}

	return &roleCondition{allowedRoles: roles}
}

type roleCondition struct {
	allowedRoles []string
}

func roleToLevel(role string) identity.Level {
	switch role {
	case "Administrator":
		return identity.HIGH_LEVEL
	case "User":
		return identity.LOW_LEVEL
	default:
		return identity.UNKNOWN_LEVEL
	}
}

func (c *roleCondition) Validate(user identity.User) identity.Level {
	for _, allowedRole := range c.allowedRoles {
		if user.InRole(allowedRole) {
			return roleToLevel(allowedRole)
		}
	}
	return roleToLevel("")
}
