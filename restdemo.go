package main

import (
	"fmt"
	"os"
	"strings"
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"time"
)

// This Struct Hold our model
type Contact struct {
	Id        bson.ObjectId `json:"_id" bson:"_id"`
	FirstName string        `json:"firstName" bson:"firstName"`
	LastName  string        `json:"lastName" bson:"lastName"`
	Email     string        `json:"email" bson:"email"`
	Phone     struct {
		Mobile string `json:"mobile" bson:"mobile"`
		Work   string `json:"work" bson:"work"`
	} `json:"phone" bson:"phone"`
	Address    string    `json:"address" bson:"address"`
	Twitter    string    `json:"twitter" bson:"twitter"`
	CreateDate time.Time `json:"createDate" bson:"createDate"`
}

type HandleRoutes struct {
	mgoSession *mgo.Session
}

func NewHandleRoutes(s *mgo.Session) *HandleRoutes {
	return &HandleRoutes{s}
}

// Send Error as a application/json; charset=UTF-8
func ErrorJson(w http.ResponseWriter, e string, c int) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(c)
	strJson, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{
		Error: e,
	})
	w.Write(strJson)
}

// Parse string and find match as specified in rfc2616-sec14
// as we support only application/json

func IsJsonResponseAccepted(str string) bool {
	if str == "" {
		return true
	}
	JsonResponseAccepted := false
	str = strings.Replace(str, " ", "", -1)
	MediaRange := strings.Split(str, ",")

	for _, MediaTypeWithSubTypeAndParams := range MediaRange {
		MediaTypeWithSubType := strings.Split(MediaTypeWithSubTypeAndParams, ";")[0]
		Tokens := strings.Split(strings.ToLower(MediaTypeWithSubType), "/")
		if len(Tokens) != 2 {
			fmt.Println("Parsed Invalid MediaType With SubType for " +
				MediaTypeWithSubTypeAndParams)
			// continue
			return false
		}
		MediaType := Tokens[0]
		MediaSubType := Tokens[1]
		if (MediaType == "*" || MediaType == "application") &&
			(MediaSubType == "*" || MediaSubType == "json") {
			isUtf8 := true
			// Check for Charset=UTF-8
			Params := strings.Split(MediaTypeWithSubTypeAndParams, ";")[1:]
			for _, Param := range Params {
				ParamTokens := strings.Split(strings.ToLower(Param), "=")
				if len(ParamTokens) != 2 {
					fmt.Println("Parsed Invalid Param for " +
						MediaTypeWithSubTypeAndParams)
					// isUtf8 = false
					return false
				}
				if ParamTokens[0] == "charset" &&
					ParamTokens[1] != "utf-8" {
					isUtf8 = false
				}
			}
			if isUtf8 {
				//return true
				JsonResponseAccepted = true
			}
			//return true
		} else {
			Params := strings.Split(MediaTypeWithSubTypeAndParams, ";")[1:]
			for _, Param := range Params {
				ParamTokens := strings.Split(strings.ToLower(Param), "=")
				if len(ParamTokens) != 2 {
					fmt.Println("Parsed Invalid Param for " +
						MediaTypeWithSubTypeAndParams)
					// isUtf8 = false
					return false
				}
			}

		}
	}

	//return false
	return JsonResponseAccepted
}

func IsContentTypeJson(str string) bool {
	if str == "" {
		return false
	}
	ContentTypeJson := false
	str = strings.Replace(str, " ", "", -1)
	MediaRange := strings.Split(str, ",")

	for _, MediaTypeWithSubTypeAndParams := range MediaRange {
		MediaTypeWithSubType := strings.Split(MediaTypeWithSubTypeAndParams, ";")[0]
		Tokens := strings.Split(strings.ToLower(MediaTypeWithSubType), "/")
		if len(Tokens) != 2 {
			fmt.Println("Parsed Invalid MediaType With SubType for " +
				MediaTypeWithSubTypeAndParams)
			// continue
			return false
		}
		MediaType := Tokens[0]
		MediaSubType := Tokens[1]
		if MediaType == "application" && MediaSubType == "json" {
			isUtf8 := true
			// Check for Charset=UTF-8
			Params := strings.Split(MediaTypeWithSubTypeAndParams, ";")[1:]
			for _, Param := range Params {
				ParamTokens := strings.Split(strings.ToLower(Param), "=")
				if len(ParamTokens) != 2 {
					fmt.Println("Parsed Invalid Param for " +
						MediaTypeWithSubTypeAndParams)
					// isUtf8 = false
					return false
				}
				if ParamTokens[0] == "charset" &&
					ParamTokens[1] != "utf-8" {
					isUtf8 = false
				}
			}
			if isUtf8 {
				//return true
				ContentTypeJson = true
			}
		} else {
			Params := strings.Split(MediaTypeWithSubTypeAndParams, ";")[1:]
			for _, Param := range Params {
				ParamTokens := strings.Split(strings.ToLower(Param), "=")
				if len(ParamTokens) != 2 {
					fmt.Println("Parsed Invalid Param for " +
						MediaTypeWithSubTypeAndParams)
					// isUtf8 = false
					return false
				}
			}

		}
	}

	//return false
	return ContentTypeJson
}

// GetContacts retrieves all contact resources
func (hr HandleRoutes) GetContacts(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	fmt.Println("In GET (all)")

	accpeptedTypes := r.Header.Get("Accept")

	if accpeptedTypes != "" {
		fmt.Println(accpeptedTypes)
		isJson := IsJsonResponseAccepted(accpeptedTypes)
		if !isJson {
			http.Error(w, "Expected application/json in accpet header", 406)
			return
		}

	}

	if IsContentTypeJson(r.Header.Get("Content-Type")) {
		fmt.Println("Type Test Passed")
	}

	accetedEncodings := r.Header.Get("Accept-Charset")
	fmt.Println(accetedEncodings)

	sessionCopy := hr.mgoSession.Copy()
	defer sessionCopy.Close()

	cc := sessionCopy.DB("contacts").C("contacts")

	var results []Contact

	// Get all contacts from mongo
	err := cc.Find(nil).All(&results)
	if err != nil {
		// panic(err)
		ErrorJson(w, err.Error(), 500)
		return
	}

	cj, _ := json.Marshal(results)

	// Write content-type, statuscode, payload
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(200)
	w.Write(cj)

	// TODO
	// Support for Pagination can be added by sending hrefs with URI for
	// present and previous, next, last, with (limit, offset) in json
	// but our frontend does not support it
	/*
	   strJson, _ := json.Marshal(struct{
	                                   Href string `json:"href"`
	                                   Items []Contact `json:"items"`
	                               }{
	                                   Href: "https://api.sibly.in/contacts",
	                                   Items: results,
	                               })
	   fmt.Println(string(strJson))
	*/

}

// PostContact creates a new contact resource
func (hr HandleRoutes) PostContact(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	fmt.Println("In POST")

	var err error

	contentType := r.Header.Get("Content-Type")

	if contentType != "" {
		fmt.Println(contentType)
		isJson := IsContentTypeJson(contentType)
		if !isJson {
			ErrorJson(w, "Expected application/json in Content-Type header", 406)
			return
		}
	}

	sessionCopy := hr.mgoSession.Copy()
	defer sessionCopy.Close()

	// Stub a contact to be populated from the body
	c := Contact{}

	// Populate the contact data
	err = json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		ErrorJson(w, err.Error(), 400)
		return
	}

	if c.FirstName == "" || c.LastName == "" {
		ErrorJson(w, "Invalid user input, Must provide a first or last name.", 400)
		return
	}

	// Add an Id
	c.Id = bson.NewObjectId()
	c.CreateDate = time.Now()

	cc := sessionCopy.DB("contacts").C("contacts")

	// Write the contact to mongo
	err = cc.Insert(c)
	if err != nil {
		ErrorJson(w, err.Error(), 500)
		return
	}

	// Marshal provided interface into JSON structure
	cj, _ := json.Marshal(c)

	// Create Location String to be sent with Location Header
	// This is the absolute Path to newly created Resource instance
	var urlStr string
	if r.URL.Scheme == "" {
		urlStr = "https"
	} else {
		urlStr = r.URL.Scheme
	}
	urlStr += "://"
	if r.URL.Host == "" {
		urlStr += "api.sibly.in"
	} else {
		urlStr += r.URL.Host
	}
	// URI sholud be escaped http://www.ietf.org/rfc/rfc2396.txt
	urlStr += r.URL.EscapedPath()
	if !strings.HasSuffix(urlStr, "/") {
		urlStr += "/"
	}
	urlStr += c.Id.Hex()

	// Write content-type, statuscode, payload
	w.Header().Set("Location", urlStr)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(201)
	// To write formatted strings fmt.Fprintf(w, "%s", str)
	// But we have []byte to send
	w.Write(cj)
}

// GetContact retrieves an individual contact resource
func (hr HandleRoutes) GetContact(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	fmt.Println("In GET")

	accpeptedTypes := r.Header.Get("Accept")

	if accpeptedTypes != "" {
		fmt.Println(accpeptedTypes)
		isJson := IsJsonResponseAccepted(accpeptedTypes)
		if !isJson {
			http.Error(w, "Expected application/json in accpet header", 406)
			return
		}
	}

	sessionCopy := hr.mgoSession.Copy()
	defer sessionCopy.Close()

	// Grab id
	id := p.ByName("id")

	// Verify id is ObjectId, otherwise bail
	if !bson.IsObjectIdHex(id) {
		ErrorJson(w, "Could not Verify ObjectId", 400)
		return
	}

	// Grab id
	oid := bson.ObjectIdHex(id)

	// Stub contact
	c := Contact{}

	cc := sessionCopy.DB("contacts").C("contacts")

	// Fetch contact
	if err := cc.FindId(oid).One(&c); err != nil {
		ErrorJson(w, err.Error(), 500)
		return
	}

	// Marshal provided interface into JSON structure
	cj, _ := json.Marshal(c)

	// Write content-type, statuscode, payload
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(200)
	w.Write(cj)
}

// RemoveContact removes an existing contact resource
func (hr HandleRoutes) RemoveContact(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	fmt.Println("IN DELETE")

	sessionCopy := hr.mgoSession.Copy()
	defer sessionCopy.Close()

	// Grab id
	id := p.ByName("id")

	// Verify id is ObjectId, otherwise bail
	if !bson.IsObjectIdHex(id) {
		ErrorJson(w, "Could not Verify ObjectId", 400)
		return
	}

	cc := sessionCopy.DB("contacts").C("contacts")
	// Grab id
	oid := bson.ObjectIdHex(id)

	// Remove contact
	if err := cc.RemoveId(oid); err != nil {
		ErrorJson(w, err.Error(), 500)
		return
	}

	// Write status
	w.WriteHeader(204)
}

// UpdateContact updates a contact resource
func (hr HandleRoutes) UpdateContact(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	fmt.Println("In PUT")

	var err error

	contentType := r.Header.Get("Content-Type")

	if contentType != "" {
		fmt.Println(contentType)
		isJson := IsContentTypeJson(contentType)
		if !isJson {
			ErrorJson(w, "Expected application/json in Content-Type header", 406)
			return
		}
	}

	sessionCopy := hr.mgoSession.Copy()
	defer sessionCopy.Close()

	// Stub a contact to be populated from the body
	c := Contact{}

	// Populate the contact data
	err = json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		ErrorJson(w, err.Error(), 400)
		return
	}

	// Grab id
	id := p.ByName("id")

	// Verify id is ObjectId, otherwise bail
	if !bson.IsObjectIdHex(id) {
		ErrorJson(w, "Could not Verify ObjectId", 400)
		return
	}

	// Grab id
	// oid := bson.ObjectIdHex(id)
	oid := bson.M{"_id": bson.ObjectIdHex(id)}

	cc := sessionCopy.DB("contacts").C("contacts")

	// Write the contact to mongo
	err = cc.Update(oid, c)
	if err != nil {
		//panic(err)
		ErrorJson(w, err.Error(), 500)
		return
	}

	w.WriteHeader(204)
}

var mongoUri = "localhost:27017"

func GetNewSession() *mgo.Session {
	uri := os.Getenv("MONGO_URI")
	if uri != "" {
		mongoUri = uri
	}
	session, err := mgo.Dial(mongoUri)
	if err != nil {
		panic(err)
	}
	//defer session.Close()

	fmt.Println("Connected to db successfully")

	// Optional. Switch the session to a monotonic behavior.
	session.SetMode(mgo.Monotonic, true)

	return session

}

func main() {

	r := httprouter.New()

	hr := NewHandleRoutes(GetNewSession())

	r.GET("/contacts", hr.GetContacts)

	r.GET("/contacts/:id", hr.GetContact)

	r.POST("/contacts", hr.PostContact)

	r.PUT("/contacts/:id", hr.UpdateContact)

	r.DELETE("/contacts/:id", hr.RemoveContact)

	http.ListenAndServe(":8080", r)

}


