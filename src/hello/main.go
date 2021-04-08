package main

import (
	"fmt"
	"log"
	"net/http"
	"github.com/gorilla/mux"
	"strconv"
	"encoding/json"
)

const port = ":5500"

func main(){

	router := mux.NewRouter()
	router.HandleFunc("/",rootPage)
	router.HandleFunc("/products/{fetchCountPercentage}",products).Methods("GET")
	
	fmt.Println("Serving @ http://localhost"+port)
	log.Fatal(http.ListenAndServe(port,router))
	
}
func rootPage(w http.ResponseWriter, r *http.Request){

	w.Write([]byte("This is root page"))
	
	
}

func products (w http.ResponseWriter, r *http.Request){
	fetchCountPercentage,errInput := strconv.ParseFloat(mux.Vars(r)["fetchCountPercentage"],64)
	fetchCount := 0
	
	if errInput != nil{
		fmt.Println(errInput.Error())
	}else{
		fetchCount= int(float64(len(productList)) * fetchCountPercentage /10)
		if fetchCount > len(productList){fetchCount = len(productList)}
	}
	
	jsonList,err := json.Marshal(productList[0:fetchCount])
	
	if err != nil {
		http.Error(w,err.Error(),http.StatusInternalServerError)
	}else{
		w.Header().Set("content-type","application/json")
		w.Write(jsonList)
	}
	
}

type product struct{
	Name string
	Price float64
	Count int
}

var productList = []product{
	product{"p1",1.0,10},
	product{"p2",2.0,9},
	product{"p3",3.0,8},
	product{"p4",4.0,7},
	product{"p5",5.0,6},
	product{"p6",6.0,5},
	product{"p7",7.0,4},
	product{"p8",8.0,3},
	product{"p9",9.0,2},
	product{"p10",10.0,1},

}