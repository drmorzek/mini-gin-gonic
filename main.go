package main

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// allow all connections by default, you may want to change this in a production application
	CheckOrigin: func(r *http.Request) bool { return true },
}

type HandlerFunc func(*Context)

type H map[string]interface{}

type HelperFunc func(string) string

type TemplateData struct {
	Data    map[string]interface{}
	Helpers map[string]HelperFunc
}

type Context struct {
	writer       http.ResponseWriter
	request      *http.Request
	params       map[string]string
	Body         map[string]interface{}
	router       *Router
	TemplateData TemplateData
	Data         H
	SessionData  map[string]interface{}
}

func NewContext(w http.ResponseWriter, r *http.Request, router *Router) *Context {
	return &Context{
		writer:       w,
		request:      r,
		params:       make(map[string]string),
		router:       router,
		TemplateData: TemplateData{},
		Data:         H{},
	}
}

func (c *Context) SetCookie(name string, value string, maxAge int) {
	http.SetCookie(c.writer, &http.Cookie{
		Name:   name,
		Value:  value,
		MaxAge: maxAge,
	})
}

func (c *Context) GetCookie(name string) (string, error) {
	cookie, err := c.request.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func (c *Context) ParseJson() error {
	body, err := ioutil.ReadAll(c.request.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, &c.Body); err != nil {
		return err
	}
	return nil
}

func (c *Context) JSON(code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		http.Error(c.writer, err.Error(), http.StatusInternalServerError)
		return
	}
	c.writer.Header().Set("Content-Type", "application/json")
	c.writer.WriteHeader(code)
	c.writer.Write(response)
}

func (c *Context) RenderTemplateFile(filename string) {
	bytes, err := ioutil.ReadFile(c.router.TemplateDir + "/" + filename)
	if err != nil {
		http.Error(c.writer, "Error reading template file", http.StatusInternalServerError)
		return
	}

	templateString := string(bytes)
	rendered := c.RenderTemplate(templateString)
	c.writer.Write([]byte(rendered))
}

func (c *Context) RenderTemplate(templateString string) string {

	for key, value := range c.TemplateData.Data {
		switch v := value.(type) {
		case []string:
			// Handle {{#each key}}...{{/each}} constructs
			startTag := fmt.Sprintf("{{#each %s}}", key)
			endTag := "{{/each}}"
			startIdx := strings.Index(templateString, startTag)
			endIdx := strings.Index(templateString, endTag)
			if startIdx != -1 && endIdx != -1 {
				// Extract the template within the each construct
				inside := templateString[startIdx+len(startTag) : endIdx]
				result := ""
				for _, item := range v {
					result += strings.ReplaceAll(inside, "{{this}}", item)
				}
				// Replace the each construct with the result
				templateString = strings.ReplaceAll(templateString, startTag+inside+endTag, result)
			}
		case bool:
			// Handle {{#if key}}...{{/if}} constructs
			startTag := fmt.Sprintf("{{#if %s}}", key)
			endTag := "{{/if}}"
			startIdx := strings.Index(templateString, startTag)
			endIdx := strings.Index(templateString, endTag)
			if startIdx != -1 && endIdx != -1 {
				// Extract the template within the if construct
				inside := templateString[startIdx+len(startTag) : endIdx]
				result := ""
				if v {
					result = inside
				}
				// Replace the if construct with the result
				templateString = strings.ReplaceAll(templateString, startTag+inside+endTag, result)
			}
		case string:
			// Replace {{key}} with value
			templateString = strings.ReplaceAll(templateString, "{{"+key+"}}", v)
		case int, int32, int64, float32, float64:
			// Replace {{key}} with the string representation of the number
			templateString = strings.ReplaceAll(templateString, "{{"+key+"}}", fmt.Sprintf("%v", v))

		}
	}

	for key, helper := range c.TemplateData.Helpers {
		// Find all occurrences of {{helper key}} in the template
		r := regexp.MustCompile("{{" + key + ` (\w+)}}`)
		matches := r.FindAllStringSubmatch(templateString, -1)

		// For each occurrence, apply the helper function
		for _, match := range matches {
			if len(match) == 2 {
				valueKey := match[1]
				value, exists := c.TemplateData.Data[valueKey]
				if exists {
					// Apply the helper function and replace in the template
					strValue, ok := value.(string)
					if ok {
						templateString = strings.ReplaceAll(templateString, match[0], helper(strValue))
					}
				}
			}
		}
	}
	return templateString
}

type Router struct {
	routes           map[string]map[string]HandlerFunc
	middlewares      map[string][]MiddlewareFunc
	globalMiddleware []MiddlewareFunc
	TemplateDir      string
	wsRoutes         map[string]HandlerFunc
}

type MiddlewareFunc func(HandlerFunc) HandlerFunc

func NewRouter() *Router {

	return &Router{
		routes:           make(map[string]map[string]HandlerFunc),
		wsRoutes:         make(map[string]HandlerFunc),
		middlewares:      make(map[string][]MiddlewareFunc),
		globalMiddleware: make([]MiddlewareFunc, 0),
	}
}

func (r *Router) SetTemplateDir(dir string) {
	r.TemplateDir = dir
}

func WrapF(f http.HandlerFunc) HandlerFunc {
	return func(ctx *Context) {
		f(ctx.writer, ctx.request)
	}
}

func WrapH(h http.Handler) HandlerFunc {
	return func(ctx *Context) {
		h.ServeHTTP(ctx.writer, ctx.request)
	}
}

func (r *Router) Run(path string) {

	log.Fatal(http.ListenAndServe(path, r))

}

func (r *Router) Use(middleware MiddlewareFunc) {
	r.globalMiddleware = append(r.globalMiddleware, middleware)
}

func (r *Router) UseForRoute(route string, middleware MiddlewareFunc) {
	r.middlewares[route] = append(r.middlewares[route], middleware)
}

func (r *Router) ServeFiles(path string, root http.FileSystem) {
	fileServer := http.FileServer(root)

	r.AddRoute("GET", path+"/*filepath", func(c *Context) {
		reqPath := c.request.URL.Path
		if strings.Contains(reqPath, "..") {
			http.NotFound(c.writer, c.request)
			return
		}
		reqPath = strings.TrimPrefix(reqPath, path)
		c.request.URL.Path = reqPath
		fileServer.ServeHTTP(c.writer, c.request)
	})
}

func (r *Router) AddWsRoute(path string, handler HandlerFunc) {
	r.wsRoutes[path] = handler
}

func (r *Router) AddRoute(method string, path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	if _, exists := r.routes[method]; !exists {
		r.routes[method] = make(map[string]HandlerFunc)
	}
	r.routes[method][path] = applyMiddleware(handler, middlewares)
}

func (r *Router) GET(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.AddRoute("GET", path, handler, middlewares...)
}
func (r *Router) POST(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.AddRoute("POST", path, handler, middlewares...)
}
func (r *Router) PUT(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.AddRoute("PUT", path, handler, middlewares...)
}
func (r *Router) DELETE(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.AddRoute("DELETE", path, handler, middlewares...)
}

func (r Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	var handler HandlerFunc
	params := make(map[string]string)
	// Проверка на наличие точных совпадений маршрутов
	if routes, ok := r.routes[req.Method]; ok {
		if h, ok := routes[req.URL.Path]; ok {
			handler = h
		} else {
			for path, h := range routes {
				routeParts := strings.Split(path, "/")
				requestParts := strings.Split(req.URL.Path, "/")
				if len(routeParts) != len(requestParts) && !strings.HasSuffix(path, "/*") {
					continue
				}
				matches := true
				for i := range routeParts {
					if routeParts[i] == requestParts[i] || (len(routeParts[i]) > 0 && routeParts[i][0] == ':') {
						if len(routeParts[i]) > 0 && routeParts[i][0] == ':' {
							params[routeParts[i][1:]] = requestParts[i]
						}
						continue
					} else if routeParts[i] == "*" {
						params["*"] = strings.Join(requestParts[i:], "/")
						break
					}
					matches = false
					break
				}
				if matches {
					handler = h
					break
				}
			}
		}
	}

	if wsHandler, ok := r.wsRoutes[req.URL.Path]; ok {
		ctx := NewContext(w, req, &r)
		// Обработка WebSocket маршрута
		wsHandler(ctx)
	} else {
		if handler != nil {
			ctx := NewContext(w, req, &r)
			ctx.params = params
			handler = applyMiddleware(handler, r.middlewares[req.URL.Path])
			handler = applyMiddleware(handler, r.globalMiddleware)
			handler(ctx)
		} else {
			http.NotFound(w, req)
		}
	}
}

func applyMiddleware(handler HandlerFunc, middlewares []MiddlewareFunc) HandlerFunc {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

// SessionStore хранит данные сессии
type SessionStore struct {
	sync.RWMutex
	Data map[string]map[string]interface{}
}

// NewSessionStore создает новый SessionStore
func NewSessionStore() *SessionStore {
	return &SessionStore{
		Data: map[string]map[string]interface{}{},
	}
}

// Get возвращает данные сессии по ID
func (s *SessionStore) Get(id string) (map[string]interface{}, bool) {
	s.RLock()
	defer s.RUnlock()
	data, exists := s.Data[id]
	return data, exists
}

// Set устанавливает данные сессии по ID
func (s *SessionStore) Set(id string, sessionData map[string]interface{}) {
	s.Lock()
	defer s.Unlock()
	s.Data[id] = sessionData
}

// sessionMiddleware создает новую сессию или восстанавливает существующую
func sessionMiddleware(store *SessionStore) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			// Пытаемся извлечь существующую сессию
			cookie, err := ctx.request.Cookie("session_id")
			var sessionData map[string]interface{}
			var sessionID string
			if err == nil {
				sessionID = cookie.Value
				sessionData, _ = store.Get(sessionID)
			}

			// Если сессия не существует, создаем новую
			if sessionData == nil {
				sessionData = make(map[string]interface{})
				sessionID = generateSessionID()
				ctx.SetCookie("session_id", sessionID, 3600) // 1 hour
				store.Set(sessionID, sessionData)
			}

			// Добавляем session_id в данные сессии
			sessionData["session_id"] = sessionID

			ctx.SessionData = sessionData

			next(ctx)
		}
	}
}

// GzipMiddleware will apply gzip compression to the response body if the client can accept it
func GzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the client can accept the gzip encoding.
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		// Set the HTTP header to gzip.
		w.Header().Set("Content-Encoding", "gzip")

		// Create a gziped response.
		gz := gzip.NewWriter(w)
		defer gz.Close()

		next.ServeHTTP(GzipResponseWriter{Writer: gz, ResponseWriter: w}, r)
	})
}

type GzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (g GzipResponseWriter) Write(b []byte) (int, error) {
	return g.Writer.Write(b)
}

func StaticCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600") // 1 hour
		next.ServeHTTP(w, r)
	})
}

// generateSessionID генерирует новый уникальный ID сессии
func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func CORSMiddleware(allowedIPs ...string) func(next HandlerFunc) HandlerFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			if len(allowedIPs) > 0 {
				originIP := strings.Split(ctx.request.RemoteAddr, ":")[0]
				allowed := false
				for _, ip := range allowedIPs {
					if ip == originIP {
						allowed = true
						break
					}
				}

				if !allowed {
					http.Error(ctx.writer, "Forbidden", http.StatusForbidden)
					return
				}
			}

			ctx.writer.Header().Set("Access-Control-Allow-Origin", "*")
			ctx.writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			ctx.writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

			if ctx.request.Method == "OPTIONS" {
				ctx.writer.WriteHeader(http.StatusOK)
				return
			}

			next(ctx)
		}
	}
}

func LoggerMiddleware1(next HandlerFunc) HandlerFunc {
	return func(ctx *Context) {
		fmt.Println("Logging1...")
		next(ctx)
	}
}
func LoggerMiddleware2(next HandlerFunc) HandlerFunc {
	return func(ctx *Context) {
		fmt.Println("Logging2...")
		next(ctx)
	}
}

func AuthMiddleware(next HandlerFunc) HandlerFunc {
	return func(ctx *Context) {
		fmt.Println("Authenticating...")
		next(ctx)
	}
}

func ValidatePostMiddleware(next HandlerFunc) HandlerFunc {
	return func(ctx *Context) {
		if err := ctx.ParseJson(); err != nil {
			ctx.JSON(http.StatusBadRequest, H{"error": "Failed to parse JSON"})
			return
		}

		// Perform validation
		if title, ok := ctx.Body["title"].(string); !ok || title == "" {
			ctx.JSON(http.StatusBadRequest, H{"error": "Missing or invalid 'title' field"})
			return
		}
		next(ctx)
	}
}

func ErrorMiddleware(next HandlerFunc) HandlerFunc {
	return func(ctx *Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("An error occurred: %v", err)
				ctx.JSON(http.StatusInternalServerError, H{"error": fmt.Sprintf("An error occurred: %v", err)})
			}
		}()
		next(ctx)
	}
}

func main() {
	router := NewRouter()

	store := NewSessionStore()
	router.Use(sessionMiddleware(store))

	router.Use(CORSMiddleware())
	// router.Use(CORSMiddleware("192.0.2.1"))
	router.Use(ErrorMiddleware)
	router.Use(LoggerMiddleware1)
	router.Use(LoggerMiddleware1)

	router.SetTemplateDir(".")

	router.AddWsRoute("/ws", func(ctx *Context) {
		// Upgrade the HTTP connection to a WebSocket connection
		ws, err := upgrader.Upgrade(ctx.writer, ctx.request, nil)
		if err != nil {
			log.Printf("error upgrading request to a websocket::%v", err)
			return
		}
		defer ws.Close()

		for {
			messageType, message, err := ws.ReadMessage()
			if err != nil {
				log.Printf("error reading message::%v", err)
				break
			}

			log.Printf("got message of type %v: %v", messageType, string(message))

			// Echo the message back
			if err := ws.WriteMessage(messageType, []byte(fmt.Sprintf("You send: %v", string(message)))); err != nil {
				log.Printf("error writing message::%v", err)
				break
			}
		}
	})

	router.AddRoute("GET", "/", func(ctx *Context) {
		fmt.Fprint(ctx.writer, "Hello, World!")
	}, AuthMiddleware)

	router.AddRoute("GET", "/posts/:id", func(ctx *Context) {
		id := ctx.params["id"]
		fmt.Fprintf(ctx.writer, "Post ID: %s", id)
	}, LoggerMiddleware2, AuthMiddleware)

	router.GET("/welcome", func(ctx *Context) {

		fmt.Println(ctx.SessionData["session_id"])
		// add some data
		ctx.TemplateData.Data = map[string]interface{}{
			"name": "John Doe",
			"age":  30,
		}

		// add some helper functions
		ctx.TemplateData.Helpers = map[string]HelperFunc{
			"uppercase": func(s string) string {
				return strings.ToUpper(s)
			},
			"lowercase": func(s string) string {
				return strings.ToLower(s)
			},
		}

		// render the template file
		ctx.RenderTemplateFile("./welcome.html")
	}, AuthMiddleware)

	router.POST("/api/posts", func(ctx *Context) {

		title := ctx.Body["title"]
		posts := []H{
			{"id": 1, "title": title},
			{"id": 2, "title": "Second Post"},
		}
		ctx.JSON(http.StatusOK, posts)
	}, ValidatePostMiddleware, LoggerMiddleware2, AuthMiddleware)

	router.GET("/files/:file/1111/:file2", func(ctx *Context) {
		filePath := ctx.params["file"]
		filePath2 := ctx.params["file2"]
		fmt.Fprintf(ctx.writer, "File Path: %s %s", filePath, filePath2)
	}, LoggerMiddleware2)

	router.ServeFiles("/static", http.Dir("path/to/your/static/files"))

	fmt.Println("Server listening on port 8080")
	router.Run(":8080")
}
