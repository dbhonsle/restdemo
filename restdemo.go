package main

import (
	//"crypto/rsa"
	//"flag"
	"fmt"
	//"io/ioutil"
	"os"
	"strings"
	//"log"
	"encoding/json"
	//"errors"
	//"github.com/dgrijalva/jwt-go"
	//"github.com/googollee/go-socket.io"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"math/rand"
	"net/http"
	//"strconv"
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

//CORS support middleware
type CorsHost struct {
	handler http.Handler
}

func NewCorsHost(handler http.Handler) *CorsHost {
	return &CorsHost{handler}
}

func (s *CorsHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers",
			"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	}
	// Stop here if its Preflighted OPTIONS request
	if r.Method == "OPTIONS" {
		return
	}
	s.handler.ServeHTTP(w, r)
}
/*
// Handle Socket.io connection with middleware
func Socketio(handler http.Handler, sioServer *socketio.Server) http.Handler {
	ourFunc := func(w http.ResponseWriter, r *http.Request) {

		path := r.URL.Path
		// route socketio requests to the socketio handler
		// and send everything else to the CORS handler
		if strings.HasPrefix(path, "/socket.io/") {
			sioServer.ServeHTTP(w, r)
		} else {
			handler.ServeHTTP(w, r)
		}
	}
	return http.HandlerFunc(ourFunc)
}
*/
/*
func postMessage(c chan string, so *socketio.Socket) {

}
*/
/*
func setSioHandlers(soc socketio.Socket) {
	var c chan bool = make(chan bool)

	fmt.Println("on connection")
	// so.Join("speedometer")

	// starting a concurrent task
	go func() {
		ticker := time.NewTicker(time.Millisecond * 500)
		for {
			select {
			case t := <-ticker.C:
				// fmt.Println("emitimg message"+ t.String())
				soc.Emit("asyncevent", t.String())
			case <-c:
				fmt.Println("disconnect message recived in concurrent goroutine")
				ticker.Stop()
				return
			}
		}
	}()

	// Emit inital speed on connection
	soc.Emit("newspeed", "20")

	soc.On("updatespeed", func(msg string) {

		newspeed := rand.Intn(80)

		soc.Emit("newspeed", strconv.Itoa(newspeed))
		//so.BroadcastTo("chat", "chat message", msg)
	})

	soc.On("disconnection", func() {
		fmt.Println("on disconnect")
		c <- true
	})
}
*/
/*
func verifyToken(tokenStr string) (bool, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	if err == nil && token.Valid {
		return true, err
	}
	fmt.Println(err)
	return false, err
}
*/

/*
func registerHandlers_jwt(sioServer *socketio.Server) {
	sioServer.On("connection", func(so socketio.Socket) {
		auth := false
		so.On("authenticate", func(msg string) {
			isValid, err := verifyToken(msg)
			if isValid {
				auth = true
				so.Emit("authenticated")
				setSioHandlers(so)
			} else {
				so.Emit("error", err.Error())
			}
		})

		go func() {
			time.Sleep(time.Millisecond * 15000)
			if !auth {
				fmt.Println("Warning ditected unauthorized connection")
				so.Emit("disconnect", "unauthorized")
			}
		}()

	})
}

func registerHandlers(sioServer *socketio.Server) {
	sioServer.On("connection", func(so socketio.Socket) {

		var c chan bool = make(chan bool)

		fmt.Println("on connection")
		// so.Join("speedometer")

		// starting a concurrent task
		go func() {
			ticker := time.NewTicker(time.Millisecond * 500)
			for {
				select {
				case t := <-ticker.C:
					// fmt.Println("emitimg message"+ t.String())
					so.Emit("asyncevent", t.String())
				case <-c:
					fmt.Println("disconnect message recived in concurrent goroutine")
					ticker.Stop()
					return
				}
			}
		}()

		// Emit inital speed on connection
		so.Emit("newspeed", "20")

		so.On("updatespeed", func(msg string) {

			newspeed := rand.Intn(80)

			so.Emit("newspeed", strconv.Itoa(newspeed))
			//so.BroadcastTo("chat", "chat message", msg)
		})

		so.On("disconnection", func() {
			fmt.Println("on disconnect")
			c <- true
		})

	})
}
*/
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
/*
// var verifyKey []byte

var keyString []byte

var verifyKey *rsa.PublicKey

// Try to find the token in an http.Request.
// This method will call ParseMultipartForm if there's no token in the header.
// Currently, it looks in the Authorization header as well as
// looking for an 'access_token' request parameter in req.Form.
func ParseFromRequest(req *http.Request, keyFunc jwt.Keyfunc) (token *jwt.Token, err error) {

	// Look for an Authorization header
	if ah := req.Header.Get("Authorization"); ah != "" {
		// Should be a bearer token
		if len(ah) > 6 && strings.ToUpper(ah[0:7]) == "BEARER " {
			return jwt.Parse(ah[7:], keyFunc)
		}
	}

	// Look for "access_token" parameter
	req.ParseMultipartForm(10e6)
	if tokStr := req.Form.Get("access_token"); tokStr != "" {
		return jwt.Parse(tokStr, keyFunc)
	}

	return nil, errors.New("no token present in request")

}
*/
/*
func Authorize(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// validate the token
		token, err := ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) {
			return verifyKey, nil
		})
		if err == nil && token.Valid {
			h(w, r, ps)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Authentication failed")
	}
}
*/
/*
func Authorize(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		bearerToken := r.Header.Get("Authorization")

		tokenString := strings.Split(bearerToken, " ")[1]

		tokenString = strings.TrimSpace(tokenString)

		// validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return verifyKey, nil
		})
		if err == nil && token.Valid {
			h(w, r, ps)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Authentication failed")
	}
}
*/

func Protected(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprint(w, "Protected!\n")
}
/*
var (
	httpAddr = flag.String("http", ":8080", "Listen address")
)
*/
func main() {
	//var err error

	//flag.Parse()
/*
	//verifyKey = []byte("jwt demo")
	keyString, err = ioutil.ReadFile("jwtrsa.pub")

	if err != nil {
		panic(err)
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(keyString)

	if err != nil {
		panic(err)
	}

	sioServer, _ := socketio.NewServer(nil)

	registerHandlers_jwt(sioServer)
*/
	r := httprouter.New()

	hr := NewHandleRoutes(GetNewSession())

	r.GET("/contacts", Authorize(hr.GetContacts))

	r.GET("/contacts/:id", Authorize(hr.GetContact))

	r.POST("/contacts", Authorize(hr.PostContact))

	r.PUT("/contacts/:id", Authorize(hr.UpdateContact))

	r.DELETE("/contacts/:id", Authorize(hr.RemoveContact))

	r.GET("/protected/", Authorize(Protected))
/*
	corsHost := NewCorsHost(r)
*/
/*
	corsHost := NewCorsHost(Socketio(r, sioServer))
*/
	//http.ListenAndServe(*httpAddr, corsHost)

	http.ListenAndServe(":8080", r)

	//http.ListenAndServe(*httpAddr, Socketio(corsHost, sioServer))

}

