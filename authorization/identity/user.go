package identity

type User interface {
	GetID() int
	GetDisplayName() string
	InRole(string) bool
	IsAuthenticated() bool
}
