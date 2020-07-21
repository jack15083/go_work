package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"golang.org/x/crypto/bcrypt"
)

type Route struct {
}

type Res struct {
	Error int    `json:"error"`
	Msg   string `json:"msg"`
}

type User struct {
	ID        int
	Username  string
	Password  string
	Avatar    string
	Mobile    string
	LastLogin float64
	LastIp    string
	TryTime   int
}

func (User) TableName() string {
	return "yy_auth_admin"
}

func (u *User) CheckPassword(plainPwd string) bool {
	byteHash := []byte(u.Password)

	err := bcrypt.CompareHashAndPassword(byteHash, []byte(plainPwd))
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

func (p *Route) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		sayhelloName(w, r)
		return
	}

	if r.URL.Path == "/login" {
		login(w, r)
		return
	}
	http.NotFound(w, r)
	return
}

func sayhelloName(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello myroute!")
}

func login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	loginRes := Res{
		Error: 1,
		Msg:   "",
	}
	username := strings.Trim(r.Form.Get("username"), " ")
	password := r.Form.Get("password")
	if username == "" {
		loginRes.Error = 101
		loginRes.Msg = "用户名不能为空"
	} else if password == "" {
		loginRes.Error = 102
		loginRes.Msg = "请输入密码"
	}

	db, err := gorm.Open("mysql", "root:jack1989@tcp(192.168.126.128:3306)/laravel_admin?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		panic("failed to connect database:" + err.Error())
	}

	defer db.Close()

	var user User
	db.Where("username = ?", username).First(&user)
	if user.ID == 0 {
		loginRes.Error = 103
		loginRes.Msg = "用户名或密码错误"
		json.NewEncoder(w).Encode(loginRes)
		return
	}

	if (time.Now().Unix()-int64(user.LastLogin)) < 3600 && user.TryTime > 5 {
		loginRes.Error = 104
		loginRes.Msg = "输错密码次数太多，请一小时后再试！"
		json.NewEncoder(w).Encode(loginRes)
		return
	}

	if !user.CheckPassword(password) {
		loginRes.Error = 103
		loginRes.Msg = "用户名或密码错误"
		json.NewEncoder(w).Encode(loginRes)
		user.TryTime += 1
		db.Save(&user)
		return
	}

	user.LastLogin = float64(time.Now().Unix())
	user.TryTime = 0
	user.LastIp = r.RemoteAddr
	db.Save(&user)

	loginRes.Error = 0
	loginRes.Msg = "登录成功"
	json.NewEncoder(w).Encode(loginRes)
}

func main1() {
	mux := &Route{}
	http.ListenAndServe(":9090", mux)
}
