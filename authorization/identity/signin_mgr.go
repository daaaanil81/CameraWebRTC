package identity

type SignManager interface {
	SignIn(user User) error
	SignOut(user User) error
	Check() (int, error)
}
