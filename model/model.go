package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID            primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
	Username      string             `json:"username" bson:"username,omitempty"`
	Password      string             `json:"password,omitempty" bson:"password,omitempty"`
	Fullname      string             `json:"fullname" bson:"fullname,omitempty"`
	Email         string             `json:"email" validate:"email" bson:"email,omitempty"`
	Token         string             `json:"token" bson:"token,omitempty"`
	Refresh_token string             `json:"refreshtoken" bson:"refreshtoken,omitempty"`
	Created_at    time.Time          `json:"createat" bson:"createat,omitempty"`
	User_id       string             `json:"userid" bson:"userid,omitempty"`
	Photo         string             `json:"photo" bson:"photo,omitempty"`
	Lastlogin     time.Time          `json:"lastlogin" bson:"lastlogin,omitempty"`
	Profile       string             `json:"profile" bson:"profile,omitempty"`
	Post          []string           `json:"post" bson:"post,omitempty"`
	Follower      []string           `json:"follower" bson:"follower,omitempty"`
	Following     []string           `json:"following" bson:"following,omitempty"`
}

type Post struct {
	ID        primitive.ObjectID `json:"_id" bson:"_id"`
	User      Userpost           `json:"user" bson:"user,omitempty"`
	Body      string             `json:"body" bson:"body,omitempty"`
	Linkphoto string             `json:"linkphoto" bson:"linkphoto,omitempty"`
	Islike    int                `json:"islike" bson:"islike,omitempty"`
	Like      int                `json:"like" bson:"like,omitempty"`
	Datetime  time.Time          `json:"datetime" bson:"datetime,omitempty"`
	Location  string             `json:"location" bson:"location,omitempty"`
	Postid    string             `json:"postid" bson:"postid,omitempty"`
}
type Userpost struct {
	Username string `json:"username" bson:"username,omitempty"`
	Photo    string `json:"photo" bson:"photo"`
}

type Comment struct {
	ID     primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
	Postid string             `json:"postid" bson:"postid,omitempty"`
	User   Userpost           `json:"user" bson:"user,omitempty"`
	Detail string             `json:"detail" bson:"detail,omitempty"`
	Time   time.Time          `json:"time" bson:"time,omitempty"`
}

type ResponseResult struct {
	Error  string `json:"error"`
	Result string `json:"result"`
}
