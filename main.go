package traefikbodyrequesttransformerx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/traefik/traefik/v3/pkg/plugins"
	"io"
	"log"
	"net/http"
	"strings"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"text/scanner"
)

type Config struct {
	RequestTransKonfigs  Configs `json:"requestTransKonfigs"`

}

type Configs []ConfigItems

type ConfigItems struct {
	JspathRequest  string `json:"jspathRequest"`
	Url  string `json:"url"`
	Method  string `json:"method"`
	Enable bool `json:"enable"`
}

func CreateConfig() *Config {
	return &Config{}
}

type Uppercase struct {
	next http.Handler
	name string
	cfg  *Config
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
	var errRequest error

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
			result, errRequest = getBodyRequestJsonPathResult(v, template2)

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
		
		return v
	default:
		return v
	}
}


func updateNativeRequest(config ConfigItems,u *Uppercase,rw http.ResponseWriter, req *http.Request) {
	var body []byte
	var err, errRequest error
	var resultSingleJsonPath string
	var resultFinalJsonPath string

	path := req.URL.Path


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


	for i, config := range u.cfg.RequestTransKonfigs  {
        if !config.Enable {
            continue
        }
		if req.URL.Path == config.Url && req.Method == config.Method {
			updateNativeRequest(config,u,rw, req)
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
	fmt.Println("hello world")

}
