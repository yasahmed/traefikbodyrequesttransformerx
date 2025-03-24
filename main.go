package traefikbodyrequesttransformerx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"strconv"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"time"
    "sync"
	"reflect"
)


var jwtCache = NewJWTCache()

// CacheEntry represents a cached result
type CacheEntry struct {
	header    JWTHeader
	claims    JWTClaims
	signature []byte
}

// JWTCache is a thread-safe in-memory cache for JWT parsing results
type JWTCache struct {
	entries map[string]CacheEntry
	mu      sync.RWMutex
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"` // Key type (e.g., "RSA")
	Kid string `json:"kid"` // Key ID
	Use string `json:"use"` // Key usage (e.g., "sig" for signature)
	N   string `json:"n"`   // Modulus (Base64 URL encoded)
	E   string `json:"e"`   // Exponent (Base64 URL encoded)
}

type JWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type JWTClaims struct {
	Exp int64 `json:"exp"`
	Jti string `json:"preferred_username"`
	//Email string `json:"email_verified,omitempty"` // Assuming email is a field
}

type Config struct {
	RequestTransKonfigs  Configs `json:"requestTransKonfigs"`
	JwksURL  string `json:"jwksURL"`


}

type Configs []ConfigItems

type ConfigItems struct {
	JspathRequest  string `json:"jspathRequest"`
	Url  string `json:"url"`
	Method  string `json:"method"`
	Enable bool `json:"enable"`
	Secure bool `json:"secure"`

}



// Get dynamically retrieves a field value by name
func (c JWTClaims) Get(fieldName string) (interface{}, error) {
	// Use reflection to get the value of the field
	val := reflect.ValueOf(c)
	field := val.FieldByName(fieldName)

	if !field.IsValid() {
		return nil, fmt.Errorf("field '%s' not found in JWTClaims", fieldName)
	}

	return field.Interface(), nil
}


func CreateConfig() *Config {
	return &Config{}
}

type Uppercase struct {
	next http.Handler
	name string
	cfg  *Config
}

// Get retrieves a cached result by key
func (c *JWTCache) Get(key string) (CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	return entry, exists
}

// Set stores a result in the cache by key
func (c *JWTCache) Set(key string, entry CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = entry
}


// NewJWTCache creates a new JWTCache instance
func NewJWTCache() *JWTCache {
	return &JWTCache{
		entries: make(map[string]CacheEntry),
	}
}


func getPublicKey(jwksURL string) (*rsa.PublicKey, error) {
    fmt.Println("Get Public Key")
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks JWKS
	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return nil, err
	}

	key := jwks.Keys[0]

	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}

	var e int
	for _, b := range eBytes {
		e = (e << 8) + int(b)
	}

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}

	return publicKey, nil
}

func parseJWT(tokenString string) (header JWTHeader, claims JWTClaims, signature []byte, err error) {

	// Check the cache first
	if entry, exists := jwtCache.Get("pubk"); exists {
		fmt.Println("Cache hit! Returning cached result.")
		return entry.header, entry.claims, entry.signature, nil
	}

	fmt.Println("Cache miss! Parsing JWT and caching result.")

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		err = errors.New("invalid JWT format")
		return
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return
	}
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		return
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	err = json.Unmarshal(claimsBytes, &claims)
	if err != nil {
		return
	}

	// Decode signature
	signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return
	}

	// Cache the result
	jwtCache.Set("pubk", CacheEntry{
		header:    header,
		claims:    claims,
		signature: signature,
	})

	return
}

func validateJWT(tokenString string, publicKey *rsa.PublicKey) (bool, error) {
	_, claims, signature, err := parseJWT(tokenString)
	if err != nil {
		return false, err
	}

	if time.Now().Unix() > claims.Exp {
		return false, errors.New("token is expired")
	}

	hasher := sha256.New()
	hasher.Write([]byte(strings.Join(strings.Split(tokenString, ".")[0:2], ".")))
	hashed := hasher.Sum(nil)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signature)
	if err != nil {
		return false, err
	}

	return true, nil
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Uppercase{
		next: next,
		name: name,
		cfg:  config,
	}, nil
}

func parseJsonPath(path string) ([]interface{}, error) {
	if !strings.HasPrefix(path, "$") {
		return nil, fmt.Errorf("path must start with $")
	}
	path = path[1:] // Remove the "$" prefix
	var steps []interface{}
	pos := 0
	for pos < len(path) {
		for pos < len(path) && path[pos] == '.' {
			pos++
		}
		if pos >= len(path) {
			break
		}
		if path[pos] == '[' {
			close := strings.IndexByte(path[pos:], ']')
			if close == -1 {
				return nil, fmt.Errorf("unclosed [ at position %d", pos)
			}
			idxStr := path[pos+1 : pos+close]
			idx, err := strconv.Atoi(idxStr)
			if err != nil {
				return nil, fmt.Errorf("invalid index: %s at position %d", idxStr, pos+1)
			}
			steps = append(steps, idx)
			pos += close + 1
		} else {
			start := pos
			for pos < len(path) && path[pos] != '.' && path[pos] != '[' {
				pos++
			}
			field := path[start:pos]
			steps = append(steps, field)
		}
	}
	return steps, nil
}

func evaluate(jsonData interface{}, steps []interface{}) (interface{}, error) {
	current := jsonData
	for _, step := range steps {
		if current == nil {
			return nil, fmt.Errorf("cannot proceed on nil")
		}
		switch s := step.(type) {
		case string:
			m, ok := current.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("expected map, got %T", current)
			}
			val, ok := m[s]
			if !ok {
				return nil, fmt.Errorf("field %s not found", s)
			}
			current = val
		case int:
			arr, ok := current.([]interface{})
			if !ok {
				return nil, fmt.Errorf("expected array, got %T", current)
			}
			if s < 0 || s >= len(arr) {
				return nil, fmt.Errorf("index %d out of range", s)
			}
			current = arr[s]
		default:
			return nil, fmt.Errorf("invalid step type: %T", step)
		}
	}
	return current, nil
}

func getBodyRequestJsonPathResult(path string, data interface{}) (string, error) {

	fmt.Println("OOOO %s %v", path, data)

	if path == "" || data == nil {
		return "", nil
	}

	steps, err := parseJsonPath(path)

	if err != nil {
		fmt.Println("Error parsing path:", err)
		return "", err
	}

	result, err := evaluate(data, steps)

	if err != nil {
		fmt.Println("Error evaluating path:", err)
		return "", err
	}
	return result.(string), nil
}

func processJSON(data interface{}, dataJSON string,  req *http.Request) interface{} {

	var result string

	var template2 map[string]interface{}
	if err := json.Unmarshal([]byte(dataJSON), &template2); err != nil {
		panic(err)
	}

	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			v[key] = processJSON(value, dataJSON,req)
		}
		return v
	case []interface{}:
		// If it's a slice, iterate over its elements.
		for i, item := range v {
			v[i] = processJSON(item, dataJSON,req)
		}
		return v
	case string:
		if strings.HasPrefix(v, "$.") {
			result, _ = getBodyRequestJsonPathResult(v, template2)

			return result
		}

		if strings.HasPrefix(v, "_$q.") {
			headerName :=  strings.Replace(v, "_$q.", "", 1)
			result := req.URL.Query().Get(headerName)
			return result

		}

		if strings.HasPrefix(v, "_$h.") {
			headerName :=  strings.Replace(v, "_$h.", "", 1)
			result := req.Header.Get(headerName)
			return result

		}

		if strings.HasPrefix(v, "_$c.") {
			headerName :=  strings.Replace(v, "_$c.", "", 1)
			
			
			if entry, exists := jwtCache.Get("pubk"); exists {
				claims := entry.claims 
	
				value, err := claims.Get(headerName)
				if err != nil {
					return ""
				}
				return value;
	
				
			}

		}


		

		
		return v
	default:
		return v
	}
}


func updateNativeRequest(config ConfigItems,u *Uppercase,rw http.ResponseWriter, req *http.Request) {
	var body []byte
	var err error




	if req.Body != nil {
		body, err = io.ReadAll(req.Body)
		if err != nil {
			fmt.Printf("Plugin %s: Failed to read request body: %v", u.name, err)
			http.Error(rw, "Failed to read request body", http.StatusBadRequest)
			return
		}

		dataJSON := string(body)

		var template map[string]interface{}
		if err := json.Unmarshal([]byte(config.JspathRequest), &template); err != nil {
			panic(err)
		}

		processedJSON := processJSON(template, dataJSON,req)


		output, err := json.MarshalIndent(processedJSON, "", "  ")
		if err != nil {
			panic(err)
		}

		req.Body = io.NopCloser(bytes.NewReader(output))

		contentLength := len(output)
		req.ContentLength = int64(contentLength)
		req.Header.Set("Content-Length", strconv.Itoa(contentLength))

	} else {
		fmt.Printf("Plugin %s: Request body is nil", u.name)
	}

}




func (u *Uppercase) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	var publicKey *rsa.PublicKey
    var err error


	if u.cfg.JwksURL != "" {
		publicKey, err = getPublicKey(u.cfg.JwksURL)
	}
	

	for _, config := range u.cfg.RequestTransKonfigs  {
        if config.Enable {

		
            
		if req.URL.Path == config.Url && req.Method == config.Method {

			if config.Secure  {

					if err != nil {
						fmt.Printf("Error getting public key: %v\n", err)
						rw.WriteHeader(http.StatusUnauthorized)
						rw.Write([]byte("Not Authorized: Error while checking Authorization"))
						return
					}
	
					authHeader := req.Header.Get("Authorization")
					if authHeader == "" {
						
						rw.WriteHeader(http.StatusUnauthorized)
						rw.Write([]byte("Not Authorized: Authorization header is missing"))
						return
					}
				
					if !strings.HasPrefix(authHeader, "Bearer ") {
						rw.WriteHeader(http.StatusUnauthorized)
						rw.Write([]byte("Not Authorized: Invalid Authorization header format"))
						return
					}
				
					token := strings.TrimPrefix(authHeader, "Bearer ")

					valid, err := validateJWT(token,publicKey)
					if err != nil {
						fmt.Println("Error validating JWT: %v\n", err)
						rw.WriteHeader(http.StatusUnauthorized)
						rw.Write([]byte("Not Authorized: Error validating JWT"))
						return
					}
	
					if valid {
						fmt.Println("Token is valid")
					} else {
						fmt.Println("Error Token is invalid: %v\n", err)
						rw.WriteHeader(http.StatusUnauthorized)
						rw.Write([]byte("Not Authorized: Token is invalid"))
						return
					}
	
			}

			updateNativeRequest(config,u,rw, req)
		}
        }

		

    }


	rec := &responseRecorder{ResponseWriter: rw}
	u.next.ServeHTTP(rec, req)


	rw.WriteHeader(rec.statusCode)
	_, _ = rw.Write([]byte(rec.body.Bytes()))
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

func main() {
	fmt.Println("Wache")

}
