package main

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
				"priority":    validateIntRange("priority", 0, 191),
				"hostname":    validateHostname("hostname"),
				"application": validateNotEmpty("application"),
				"pid":         validateIntRange("pid", 1, 10000),
				"message":     validateNotEmpty("message"),
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
				"priority":        validateIntRange("priority", 0, 191),
				"version":         validateIntRange("version", 1, 3),
				"hostname":        validateHostname("hostname"),
				"application":     validateNotEmpty("application"),
				"pid":             validateIntRange("pid", 1, 10000),
				"message-id":      validateIntRange("message-id", 1, 1000),
				"structured-data": validateEquals("-", "structured-data"),
				"message":         validateNotEmpty("message"),
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
				"host":            validateIPV4Address("host"),
				"user-identifier": validateLowerCase("user-identifier"),
				"auth-user-id":    validateNotEmpty("auth-user-id"), // Assuming validation needed is non-empty
				"method":          validateHTTPMethod("method"),
				"request":         validateStartsWith("request", "/"),
				"protocol":        validateStartsWith("protocol", "HTTP/"),
				"response-code":   validateIntRange("response-code", 100, 599),
				"bytes":           validateIntRange("bytes", 0, 30000),
			},
		},

		{
			name: "crowdstrike falcon data replicator example",
			fields: map[string]string{
				"LocalAddressIP4":            "{{ .IPV4Address }}",
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
				"LocalAddressIP4":            validateIPV4Address("LocalAddressIP4"),
				"aip":                        validateIPV4Address("aip"),
				"RemoteAddressIP4":           validateIPV4Address("RemoteAddressIP4"),
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
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
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
			}
		})
	}
}

func validateOneOf(field string, validValues ...string) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		value := data[field]
		found := false
		for _, valid := range validValues {
			if value == valid {
				found = true
				break
			}
		}
		assert.True(t, found, "Value '%s' for field '%s' is not one of the valid values", value, field)
	}
}

func validateIntRange(field string, min, max int) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		val, err := strconv.Atoi(data[field])
		assert.NoError(t, err, "Value is not an integer")
		assert.True(t, val >= min && val <= max, "Value %d is out of range (%d - %d)", val, min, max)
	}
}

var validUUIDRegexp = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[4][a-fA-F0-9]{3}-[89ABab][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`)

func validateUUID(field string) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		isValidUUID := validUUIDRegexp.MatchString(data[field])
		assert.True(t, isValidUUID, "UUID does not appear to be valid: %s", data[field])
	}
}

func validateHostname(field string) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		hostname := data[field]
		assert.NotEmpty(t, hostname, "hostname is empty")
		assert.Equal(t, strings.ToLower(hostname), hostname, "hostname is not in lower case")
	}
}

func validateNotEmpty(field string) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		assert.NotEmpty(t, data[field], "%s is empty", field)
	}
}

func validateEquals(expectedValue, field string) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		assert.Equal(t, expectedValue, data[field], "%s does not match the expected value", field)
	}
}

func validateLowerCase(field string) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		assert.Equal(t, strings.ToLower(data[field]), data[field], "%s is not in lower case: %s", field, data[field])
	}
}

func validateHTTPMethod(field string) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		validMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
		assert.Contains(t, validMethods, data[field], "method %s is not a valid HTTP method", data[field])
	}
}

func validateStartsWith(field string, prefix string) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		assert.True(t, strings.HasPrefix(data[field], prefix), "%s does not start with '%s': %s", field, prefix, data[field])
	}
}

func validateIPV4Address(field string) func(map[string]string, *testing.T) {
	return func(data map[string]string, t *testing.T) {
		ip := net.ParseIP(data[field])
		assert.NotNil(t, ip, "The IP address in %s is not valid: %s", field, data[field])
		assert.Equal(t, 4, len(ip.To4()), "The IP address in %s is not a valid IPv4 address: %s", field, data[field])
	}
}
