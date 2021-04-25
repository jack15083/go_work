package user

var user User

type User struct {
	name  string
	Where string
}

func InitUser() {
	user.name = "name1"
}

func GetUser() *User {
	return &user
}
