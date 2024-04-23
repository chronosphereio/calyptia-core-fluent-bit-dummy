package main

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestLogGenerator(t *testing.T) {
	cases := []struct {
		name    string
		fields  map[string]string
		asserts map[string]func(data map[string]string, t *testing.T)
	}{
		{
			name: "syslog rfc3164 example",
			fields: map[string]string{
				"priority":    "{{ .Priority }}",
				"hostname":    "{{ .Username }}",
				"application": "{{ .Application }}",
				"pid":         "{{ .PID }}",
				"message":     "{{ .Message }}",
			},
			asserts: map[string]func(data map[string]string, t *testing.T){
				"priority": func(data map[string]string, t *testing.T) {
					priority, err := strconv.Atoi(data["priority"])
					if err != nil {
						t.Errorf("priority is not an integer")
					}
					if priority < 0 || priority > 191 {
						t.Errorf("priority %d is out of the expected range (0-191)", priority)
					}
				},
				"hostname": func(data map[string]string, t *testing.T) {
					hostname := data["hostname"]
					if hostname == "" {
						t.Errorf("hostname is empty")
					}
					if strings.ToLower(hostname) != hostname {
						t.Errorf("hostname is not in lower case")
					}
				},
				"application": func(data map[string]string, t *testing.T) {
					if application := data["application"]; application == "" {
						t.Errorf("application is empty")
					}
				},
				"pid": func(data map[string]string, t *testing.T) {
					pid, err := strconv.Atoi(data["pid"])
					if err != nil {
						t.Errorf("pid is not an integer")
					}
					if pid < 1 || pid > 10000 {
						t.Errorf("pid %d is out of the expected range (1-10000)", pid)
					}
				},
				"message": func(data map[string]string, t *testing.T) {
					if message := data["message"]; message == "" {
						t.Errorf("message is empty")
					}
				},
			},
		},

		{
			name: "syslog rfc5424 example",
			fields: map[string]string{
				"priority":        "{{ .Priority }}",
				"version":         "{{ randInt 1 3 }}",
				"hostname":        "{{ .Hostname }}",
				"application":     "{{ .Application }}",
				"pid":             "{{ .PID }}",
				"message-id":      "{{ randInt 1 1000 }}",
				"structured-data": "-",
				"message":         "{{ .Message }}",
			},
			asserts: map[string]func(data map[string]string, t *testing.T){
				"priority": func(data map[string]string, t *testing.T) {
					priority, err := strconv.Atoi(data["priority"])
					if err != nil {
						t.Errorf("priority is not an integer")
					}
					if priority < 0 || priority > 191 {
						t.Errorf("priority %d is out of the expected range (0-191)", priority)
					}
				},
				"version": func(data map[string]string, t *testing.T) {
					version, err := strconv.Atoi(data["version"])
					if err != nil {
						t.Errorf("version is not an integer")
					}
					if version < 1 || version > 3 {
						t.Errorf("version %d is out of the expected range (1-3)", version)
					}
				},
				"hostname": func(data map[string]string, t *testing.T) {
					hostname := data["hostname"]
					if hostname == "" {
						t.Errorf("hostname is empty")
					}
					if strings.ToLower(hostname) != hostname {
						t.Errorf("hostname is not in lower case")
					}
				},
				"application": func(data map[string]string, t *testing.T) {
					if application := data["application"]; application == "" {
						t.Errorf("application is empty")
					}
				},
				"pid": func(data map[string]string, t *testing.T) {
					pid, err := strconv.Atoi(data["pid"])
					if err != nil {
						t.Errorf("pid is not an integer")
					}
					if pid < 1 || pid > 10000 {
						t.Errorf("pid %d is out of the expected range (1-10000)", pid)
					}
				},
				"message-id": func(data map[string]string, t *testing.T) {
					messageID, err := strconv.Atoi(data["message-id"])
					if err != nil {
						t.Errorf("message-id is not an integer")
					}
					if messageID < 1 || messageID > 1000 {
						t.Errorf("message-id %d is out of the expected range (1-1000)", messageID)
					}
				},
				"structured-data": func(data map[string]string, t *testing.T) {
					if structuredData := data["structured-data"]; structuredData != "-" {
						t.Errorf("structured-data is expected to be '-', got %s", structuredData)
					}
				},
				"message": func(data map[string]string, t *testing.T) {
					if message := data["message"]; message == "" {
						t.Errorf("message is empty")
					}
				},
			},
		},

		{
			name: "apache common log example",
			fields: map[string]string{
				"host":            "{{ .IPAddress }}",
				"user-identifier": "{{ .Username }}",
				"auth-user-id":    "{{ .AuthUserID }}",
				"method":          "{{ .HTTPMethod }}",
				"request":         "{{ .HTTPPath }}",
				"protocol":        "{{ .HTTPProtocol }}",
				"response-code":   "{{ .HTTPStatusCode }}",
				"bytes":           "{{ randInt 0 30000 }}",
			},
			asserts: map[string]func(data map[string]string, t *testing.T){
				"host": func(data map[string]string, t *testing.T) {
					if !strings.Contains(data["host"], ".") {
						t.Errorf("host does not contain a valid IP address: %s", data["host"])
					}
				},
				"user-identifier": func(data map[string]string, t *testing.T) {
					if user := data["user-identifier"]; strings.ToLower(user) != user {
						t.Errorf("user-identifier is not in lower case: %s", user)
					}
				},
				"auth-user-id": func(data map[string]string, t *testing.T) {
					// Add validation as needed based on `randAuthUserID()` characteristics
				},
				"method": func(data map[string]string, t *testing.T) {
					method := data["method"]
					validMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
					found := false
					for _, v := range validMethods {
						if method == v {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("method %s is not a valid HTTP method", method)
					}
				},
				"request": func(data map[string]string, t *testing.T) {
					request := data["request"]
					if !strings.HasPrefix(request, "/") {
						t.Errorf("request does not start with '/': %s", request)
					}
				},
				"protocol": func(data map[string]string, t *testing.T) {
					protocol := data["protocol"]
					if !strings.HasPrefix(protocol, "HTTP/") {
						t.Errorf("protocol does not start with 'HTTP/': %s", protocol)
					}
				},
				"response-code": func(data map[string]string, t *testing.T) {
					code, err := strconv.Atoi(data["response-code"])
					if err != nil {
						t.Errorf("response-code is not an integer")
					}
					if code < 100 || code > 599 {
						t.Errorf("response-code %d is out of the expected range (100-599)", code)
					}
				},
				"bytes": func(data map[string]string, t *testing.T) {
					bytes, err := strconv.Atoi(data["bytes"])
					if err != nil {
						t.Errorf("bytes is not an integer")
					}
					if bytes < 0 || bytes > 30000 {
						t.Errorf("bytes %d is out of the expected range (0-30000)", bytes)
					}
				},
			},
		},

		{
			name: "crowdstrike falcon data replicator example",
			fields: map[string]string{
				"LocalAddressIP4":            "{{ .IPAddress }}",
				"event_simpleName":           "{{ randValue \"NetworkConnectIP4\" \"NetworkDisconnectIP4\" }}",
				"name":                       "{{ randValue \"NetworkConnectIP4V10\" \"NetworkDisconnectIP4V10\" }}",
				"ConfigStateHash":            "{{ randInt 65535 4294967295 }}",
				"ConnectionFlags":            "{{ randInt 0 8 }}",
				"ContextProcessId":           "{{ randInt 128 65535 }}",
				"RemotePort":                 "{{ randInt 0 65535 }}",
				"aip":                        "{{ randIPV4Address }}",
				"ConfigBuild":                "{{ .BuildVersion }}",
				"event_platform":             "{{ randValue \"Win\" \"Linux\" \"Mac\"}}",
				"LocalPort":                  "{{ randInt 0 65535 }}",
				"Entitlements":               "{{ randInt 0 32 }}",
				"EventOrigin":                "{{ randInt 0 4 }}",
				"id":                         "{{ uuidv4 }}",
				"Protocol":                   "{{ randInt 2 8 }}",
				"EffectiveTransmissionClass": "{{ randInt 2 8 }}",
				"aid":                        "{{ uuidv4 }}",
				"RemoteAddressIP4":           "{{ randIPV4Address }}",
				"ConnectionDirection":        "{{ randInt 0 1 }}",
				"InContext":                  "{{ randInt 0 1 }}",
				"cid":                        "{{ uuidv4 }}",
			},
			asserts: map[string]func(data map[string]string, t *testing.T){
				"LocalAddressIP4":            validateIPAddress("LocalAddressIP4"),
				"aip":                        validateIPAddress("aip"),
				"RemoteAddressIP4":           validateIPAddress("RemoteAddressIP4"),
				"event_simpleName":           validateOneOf("event_simpleName", "NetworkConnectIP4", "NetworkDisconnectIP4"),
				"name":                       validateOneOf("name", "NetworkConnectIP4V10", "NetworkDisconnectIP4V10"),
				"event_platform":             validateOneOf("event_platform", "Win", "Linux", "Mac"),
				"ConfigStateHash":            validateIntRange("ConfigStateHash", 65535, 4294967295),
				"ConnectionFlags":            validateIntRange("ConnectionFlags", 0, 8),
				"ContextProcessId":           validateIntRange("ContextProcessId", 128, 65535),
				"RemotePort":                 validateIntRange("RemotePort", 0, 65535),
				"LocalPort":                  validateIntRange("LocalPort", 0, 65535),
				"Entitlements":               validateIntRange("Entitlements", 0, 32),
				"EventOrigin":                validateIntRange("EventOrigin", 0, 4),
				"Protocol":                   validateIntRange("Protocol", 2, 8),
				"EffectiveTransmissionClass": validateIntRange("EffectiveTransmissionClass", 2, 8),
				"ConnectionDirection":        validateIntRange("ConnectionDirection", 0, 1),
				"InContext":                  validateIntRange("InContext", 0, 1),
				"id":                         validateUUID("id"),
				"aid":                        validateUUID("aid"),
				"cid":                        validateUUID("cid"),
			},
		},
	}

	for _, tc := range cases {
		for i := 0; i < 10; i++ {
			t.Run(fmt.Sprintf("%s-%d", tc.name, i), func(t *testing.T) {
				g := NewLogGenerator()
				for field, tmpl := range tc.fields {
					err := g.SetLogFieldTemplate(field, tmpl)
					if err != nil {
						t.Errorf("unexpected error: %s", err)
					}
				}

				data, err := g.Generate()
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				}

				for _, assert := range tc.asserts {
					assert(data, t)
				}
			})
		}
	}
}

// Define helper functions to validate test fields
func validateIPAddress(field string) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		if !strings.Contains(data[field], ".") {
			t.Errorf("IP address is not valid: %s", data["LocalAddressIP4"])
		}
	}
}

func validateOneOf(field string, validValues ...string) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		value := data[field]
		for _, valid := range validValues {
			if value == valid {
				return
			}
		}
		t.Errorf("Value '%s' for field '%s' is not one of the valid values", value, field)
	}
}

func validateIntRange(field string, min, max int) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		val, err := strconv.Atoi(data[field])
		if err != nil {
			t.Errorf("Value is not an integer: %s", err)
			return
		}
		if val < min || val > max {
			t.Errorf("Value %d is out of range (%d - %d)", val, min, max)
		}
	}
}

func validateUUID(field string) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		if len(data[field]) != 36 { // UUID with hyphens
			t.Errorf("UUID does not appear to be valid: %s", data[field])
		}
	}
}
