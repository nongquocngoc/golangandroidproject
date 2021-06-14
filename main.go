package main

import (
	"context"
	"encoding/json"
	"fmt"
	"go-login/model"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// var cookieHandler = securecookie.New(
// 	securecookie.GenerateRandomKey(64),
// 	securecookie.GenerateRandomKey(32))

// func getUserName(request *http.Request) (userName string) {
// 	if cookie, err := request.Cookie("session"); err == nil {
// 		cookieValue := make(map[string]string)
// 		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
// 			userName = cookieValue["name"]
// 		}
// 	}
// 	return userName
// }

// func setSession(userName string, response http.ResponseWriter) {
// 	value := map[string]string{
// 		"name": userName,
// 	}
// 	if encoded, err := cookieHandler.Encode("session", value); err == nil {
// 		cookie := &http.Cookie{
// 			Name:  "session",
// 			Value: encoded,
// 			Path:  "/",
// 		}
// 		http.SetCookie(response, cookie)
// 	}
// }

// func clearSession(response http.ResponseWriter) {
// 	cookie := &http.Cookie{
// 		Name:   "session",
// 		Value:  "",
// 		Path:   "/",
// 		MaxAge: -1,
// 	}
// 	http.SetCookie(response, cookie)
// }

func GetDBCollection() (*mongo.Collection, error) {

	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return nil, err
	}
	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return nil, err
	}
	collection := client.Database("gologin").Collection("users")
	return collection, nil
}

func GetDBCollectionpost() (*mongo.Collection, error) {

	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return nil, err
	}
	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return nil, err
	}
	collectionpost := client.Database("gologin").Collection("posts")
	return collectionpost, nil
}

func GetDBCollectioncomment() (*mongo.Collection, error) {

	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return nil, err
	}
	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return nil, err
	}
	collectioncomment := client.Database("gologin").Collection("comment")

	return collectioncomment, nil
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user model.User
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &user)

	var res model.ResponseResult
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	collection, err := GetDBCollection()

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	var result model.User

	err = collection.FindOne(context.TODO(), bson.D{{"username", user.Username}}).Decode(&result)
	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)

			if err != nil {
				res.Error = "Error While Hasing Password, Try Again"
				json.NewEncoder(w).Encode(res)
				return
			}
			user.Password = string(hash)
			user.Created_at = time.Now()

			_, err = collection.InsertOne(context.TODO(), user)
			if err != nil {
				res.Error = "Error While Creating User, Try Again"
				json.NewEncoder(w).Encode(res)
				return
			}

			result.ID = primitive.NewObjectID()
			// hash, err = bcrypt.GenerateFromPassword([]byte(user.Username), 5)
			// if err != nil {
			// 	res.Error = err.Error()
			// 	json.NewEncoder(w).Encode(res)
			// 	return
			// }
			_, err = collection.UpdateOne(context.TODO(), bson.M{"username": bson.M{"$eq": user.Username}}, bson.M{"$set": bson.M{"userid": result.ID.Hex()}})
			if err != nil {
				res.Error = err.Error()
				json.NewEncoder(w).Encode(res)
				return
			}
			json.NewEncoder(w).Encode(user)
			return
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
	res.Result = "Username already Exitsts!!!"
	json.NewEncoder(w).Encode(res)

}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user model.User
	// redirectTarget := "/"
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &user)

	if err != nil {
		log.Fatal(err)
	}

	collection, err := GetDBCollection()

	if err != nil {
		log.Fatal(err)
	}

	var result model.User
	var res model.ResponseResult

	err = collection.FindOne(context.TODO(), bson.D{{"username", user.Username}}).Decode(&result)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))

	if err != nil {
		res.Error = "invalid passoword"
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// setSession(user.Username, w)
	// redirectTarget = "/profile"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":    result.Email,
		"fullname": result.Fullname,
		"userid":   result.User_id,
		"username": result.Username,
	})

	tokenString, err := token.SignedString([]byte("scerret"))
	result.Token = tokenString
	if err != nil {
		res.Error = "tao token loi"
		json.NewEncoder(w).Encode(res)
		return
	}

	_, err = collection.UpdateOne(context.TODO(), bson.M{"username": bson.M{"$eq": result.Username}}, bson.M{"$set": bson.M{"token": tokenString}})

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	result.Token = tokenString
	result.Password = ""

	json.NewEncoder(w).Encode(result)
}

func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	//normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := ExtractToken(r)
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, nil
		}
		return []byte("scerret"), nil
	})

	var result model.User
	var res model.ResponseResult
	collection, err := GetDBCollection()
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		result.Username = claims["username"].(string)
		err = collection.FindOne(context.TODO(), bson.D{{"username", result.Username}}).Decode(&result)
		if result.Token == tokenString {
			json.NewEncoder(w).Encode(result)
			return
		}
	} else {
		w.WriteHeader(http.StatusForbidden)
		return
	}
}

func main() {
	fmt.Printf("Sever on: ")

	r := mux.NewRouter()
	r.HandleFunc("/", homepage)

	r.HandleFunc("/people", people).Methods("GET")

	r.HandleFunc("/register", RegisterHandler).Methods("POST")

	r.HandleFunc("/login", LoginHandler).Methods("POST")

	r.HandleFunc("/profile", ProfileHandler).Methods("GET")

	r.HandleFunc("/people/{id}", getPersonByID).Methods("GET")

	r.HandleFunc("/people/find/{id}", getPersonByUsername).Methods("POST")

	r.HandleFunc("/people/{id}", updatePerson).Methods("PUT")

	r.HandleFunc("/people/{id}", Delete).Methods("Delete")

	r.HandleFunc("/people/follower/{id}", Follower).Methods("POST")

	r.HandleFunc("/people/{id}/following", Following).Methods("POST")

	r.HandleFunc("/people/{id}/unfollowing", Unfollowing).Methods("POST")

	r.HandleFunc("/feeds", Feeds).Methods("GET")

	r.HandleFunc("/createpost", CreatePost).Methods("POST")

	r.HandleFunc("/updatepost/{id}", UpdatePost).Methods("POST")

	r.HandleFunc("/deletepost/{id}", DeletePost).Methods("POST")

	r.HandleFunc("/feeds/{id}", getPostByUsername).Methods("GET")

	r.HandleFunc("/changepass/{id}", UpdatePassword).Methods("POST")

	r.HandleFunc("/comment", CreateComment).Methods("POST")

	r.HandleFunc("/comment/{id}", GetCommentByPost).Methods("GET")

	fmt.Println("Serving @ http:localhost:5500")
	log.Fatal(http.ListenAndServe(":5500", r))
}

func GetCommentByPost(w http.ResponseWriter, r *http.Request) {
	collectioncomment, _ := GetDBCollectioncomment()
	w.Header().Set("content-type", "application/json")
	var comments []model.Comment
	id := (mux.Vars(r)["id"])
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	cursor, err := collectioncomment.Find(ctx, bson.M{"postid": id})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var comment model.Comment
		cursor.Decode(&comment)
		comments = append(comments, comment)
	}
	if err := cursor.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(w).Encode(comments)

}

func CreateComment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var comment model.Comment
	// var user model.User
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &comment)
	var res model.ResponseResult
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	collectioncomment, _ := GetDBCollectioncomment()

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	_, err = collectioncomment.InsertOne(context.TODO(), comment)
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	json.NewEncoder(w).Encode(comment)
}

// func ChangePost(w http.ResponseWriter, r *http.Request) {
// 	collection, _ := GetDBCollection()
// 	w.Header().Set("content-type", "application/json")
// 	var person model.User
// 	id, _ := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
// 	json.NewDecoder(r.Body).Decode(&person)
// 	person.Follower = person.Follower
// 	person.Following = person.Following
// 	hash, _ := bcrypt.GenerateFromPassword([]byte(person.Password), 5)
// 	person.ID = person.ID
// 	person.Email = person.Email
// 	person.Fullname = person.Fullname
// 	person.Lastlogin = person.Lastlogin
// 	person.Photo = person.Photo
// 	person.Profile = person.Profile
// 	person.Refresh_token = person.Refresh_token
// 	person.Created_at = person.Created_at
// 	person.User_id = id.Hex()
// 	person.Password = string(hash)

// 	_, err := collection.UpdateOne(context.TODO(), bson.M{"_id": bson.M{"$eq": id}}, bson.M{"$set": &person})

// 	if err != nil {
// 		w.WriteHeader(http.StatusInternalServerError)
// 		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
// 		return
// 	}

// 	json.NewEncoder(w).Encode(person)

// }

func DeletePost(w http.ResponseWriter, r *http.Request) {
	collectionpost, err := GetDBCollectionpost()
	w.Header().Set("content-type", "application/json")
	id, _ := primitive.ObjectIDFromHex(mux.Vars(r)["id"])

	_, err = collectionpost.DeleteOne(context.TODO(), bson.M{"_id": id})

	if err != nil {
		json.NewEncoder(w).Encode("loi khi xoa")
		return
	}

	json.NewEncoder(w).Encode("xoa thanh cong")
}

func CreatePost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var post model.Post
	// var user model.User
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &post)
	var res model.ResponseResult
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	collectionpost, _ := GetDBCollectionpost()
	collection, _ := GetDBCollection()
	post.ID = primitive.NewObjectID()
	post.Datetime = time.Now()
	post.Islike = 1
	post.Like = 1

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	_, err = collectionpost.InsertOne(context.TODO(), post)
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	_, err = collection.UpdateOne(context.TODO(), bson.M{"username": post.User.Username}, bson.M{"$addToSet": bson.M{"post": post.ID.Hex()}})
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	json.NewEncoder(w).Encode(post)
}

func UpdatePost(w http.ResponseWriter, r *http.Request) {
	collectionpost, _ := GetDBCollectionpost()
	w.Header().Set("Content-Type", "application/json")
	id, _ := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
	var post model.Post
	json.NewDecoder(r.Body).Decode(&post)
	var res model.ResponseResult
	json.NewDecoder(r.Body).Decode(&post)
	post.ID = id

	_, err := collectionpost.UpdateOne(context.TODO(), bson.M{"_id": bson.M{"$eq": id}}, bson.M{"$set": &post})

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	json.NewEncoder(w).Encode(post)
}

func Feeds(w http.ResponseWriter, r *http.Request) {
	collectionpost, _ := GetDBCollectionpost()
	w.Header().Set("content-type", "application/json")
	var posts []model.Post
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	cursor, err := collectionpost.Find(ctx, bson.M{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var post model.Post
		cursor.Decode(&post)
		posts = append(posts, post)
	}
	if err := cursor.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(w).Encode(posts)
}

func getPostByUsername(w http.ResponseWriter, r *http.Request) {
	collectionpost, _ := GetDBCollectionpost()
	w.Header().Set("content-type", "application/json")
	var posts []model.Post
	id := (mux.Vars(r)["id"])
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	cursor, err := collectionpost.Find(ctx, bson.M{"postid": id})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var post model.Post
		cursor.Decode(&post)
		posts = append(posts, post)
	}
	if err := cursor.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(w).Encode(posts)
}

func UpdatePassword(response http.ResponseWriter, request *http.Request) {
	collection, _ := GetDBCollection()
	response.Header().Set("content-type", "application/json")
	var person model.User
	id, _ := primitive.ObjectIDFromHex(mux.Vars(request)["id"])
	json.NewDecoder(request.Body).Decode(&person)
	hash, _ := bcrypt.GenerateFromPassword([]byte(person.Password), 5)
	person.User_id = id.Hex()
	person.Password = string(hash)

	_, err := collection.UpdateOne(context.TODO(), bson.M{"_id": bson.M{"$eq": id}}, bson.M{"$set": &person})

	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(response).Encode(person)
}

func updatePerson(response http.ResponseWriter, request *http.Request) {
	collection, _ := GetDBCollection()
	collectionspost, _ := GetDBCollectionpost()
	response.Header().Set("content-type", "application/json")
	var person model.User
	id, _ := primitive.ObjectIDFromHex(mux.Vars(request)["id"])
	json.NewDecoder(request.Body).Decode(&person)
	// person.Follower = person.Follower
	// person.Following = person.Following
	// hash, _ := bcrypt.GenerateFromPassword([]byte(person.Password), 5)
	// person.ID = person.ID
	// person.Email = person.Email
	// person.Fullname = person.Fullname
	// person.Lastlogin = person.Lastlogin
	// person.Photo = person.Photo
	// person.Profile = person.Profile
	// person.Refresh_token = person.Refresh_token
	// person.Created_at = person.Created_at
	person.User_id = id.Hex()
	// person.Password = string(hash)

	_, err := collection.UpdateOne(context.TODO(), bson.M{"_id": bson.M{"$eq": id}}, bson.M{"$set": &person})

	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	_, err = collectionspost.UpdateMany(context.TODO(), bson.M{"postid": bson.M{"$eq": person.User_id}}, bson.M{"$set": bson.M{"user": bson.M{"username": person.Fullname, "photo": person.Photo}}})
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}

	json.NewEncoder(response).Encode(person)
}

func Follower(w http.ResponseWriter, r *http.Request) {
	collection, _ := GetDBCollection()
	w.Header().Set("content-type", "application/json")
	var user model.User
	var people []model.User
	id, _ := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
	json.NewDecoder(r.Body).Decode(&user)
	curent, err := collection.Find(context.TODO(), bson.D{{"following", id.Hex()}})
	if err != nil {
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	var result model.User

	defer curent.Close(context.TODO())

	for curent.Next(context.TODO()) {
		var person model.User
		curent.Decode(&person)
		_, err = collection.UpdateOne(context.TODO(), bson.M{"_id": bson.M{"$eq": id}}, bson.M{"$addToSet": bson.M{"follower": person.User_id}})
		if err != nil {
			w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			return
		}
		result.ID = person.ID
		result.Username = person.Username
		result.Fullname = person.Fullname
		result.Following = person.Following
		// json.NewEncoder(w).Encode(result)
		people = append(people, result)
	}
	json.NewEncoder(w).Encode(people)
}

func Following(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	var user model.User
	var res model.ResponseResult
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &user)
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	collection, err := GetDBCollection()
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	err = collection.FindOne(context.TODO(), bson.D{{"username", user.Username}}).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "khong tim thay user"}`))
		return
	}
	id, _ := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
	var result model.User

	_, err = collection.UpdateOne(context.TODO(), bson.M{"username": bson.M{"$eq": user.Username}}, bson.M{"$addToSet": bson.M{"follower": bson.M{"$each": bson.A{id.Hex()}}}})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}

	_, err = collection.UpdateOne(context.TODO(), bson.M{"_id": bson.M{"$eq": id}}, bson.M{"$addToSet": bson.M{"following": bson.M{"$each": bson.A{user.User_id}}}})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}

	err = collection.FindOne(context.TODO(), bson.M{"_id": bson.M{"$eq": id}}).Decode(&result)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	result.Password = ""

	json.NewEncoder(w).Encode(&result)
}

func people(w http.ResponseWriter, r *http.Request) {
	collection, err := GetDBCollection()
	w.Header().Set("content-type", "application/json")
	var people []model.User
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var person model.User
		cursor.Decode(&person)
		people = append(people, person)
	}
	if err := cursor.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(w).Encode(people)
}

func getPersonByID(w http.ResponseWriter, r *http.Request) {
	collection, err := GetDBCollection()
	w.Header().Set("content-type", "application/json")
	var person model.User
	id, _ := primitive.ObjectIDFromHex(mux.Vars(r)["id"])

	err = collection.FindOne(context.TODO(), bson.D{{"_id", id}}).Decode(&person)
	person.Password = ""
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(w).Encode(person)

}

func getPersonByUsername(w http.ResponseWriter, r *http.Request) {
	collection, err := GetDBCollection()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	w.Header().Set("content-type", "application/json")
	var person model.User
	name := mux.Vars(r)["id"]
	err = collection.FindOne(context.TODO(), bson.M{"username": name}).Decode(&person)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	person.Password = ""
	json.NewEncoder(w).Encode(&person)

}

func Delete(w http.ResponseWriter, r *http.Request) {
	collection, err := GetDBCollection()
	w.Header().Set("content-type", "application/json")
	id, _ := primitive.ObjectIDFromHex(mux.Vars(r)["id"])

	_, err = collection.DeleteMany(context.TODO(), bson.M{"_id": id})

	if err != nil {
		json.NewEncoder(w).Encode("loi khi xoa")
		return
	}

	json.NewEncoder(w).Encode("xoa thanh cong")
}

func Unfollowing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	var user model.User
	var res model.ResponseResult
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &user)
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	collection, err := GetDBCollection()
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	err = collection.FindOne(context.TODO(), bson.D{{"username", user.Username}}).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "khong tim thay user"}`))
		return
	}

	id, _ := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
	_, err = collection.UpdateMany(context.TODO(), bson.M{"_id": bson.M{"$eq": id}}, bson.M{"$pull": bson.M{"following": user.User_id}})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	var result model.User

	_, err = collection.UpdateOne(context.TODO(), bson.M{"username": bson.M{"$eq": user.Username}}, bson.M{"$pull": bson.M{"follower": id.Hex()}})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(w).Encode(result)
}

func homepage(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode("This Is Root Page")
}
