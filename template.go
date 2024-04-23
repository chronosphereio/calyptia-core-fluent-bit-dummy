package main

import (
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/brianvoe/gofakeit"
)

type LogGenerator struct {
	templateFuncMap   template.FuncMap
	logFieldTemplates map[string]*template.Template
}

func NewLogGenerator() *LogGenerator {
	templateFuncMap := sprig.TxtFuncMap()
	templateFuncMap["randValue"] = func(values ...string) string {
		return values[rand.Intn(len(values))]
	}
	templateFuncMap["randInt"] = func(min, max int) string {
		return strconv.Itoa(gofakeit.Number(min, max))
	}
	templateFuncMap["randFloat"] = func(min, max float64) string {
		return fmt.Sprintf("%.2f", gofakeit.Float64Range(min, max))
	}
	templateFuncMap["randIPAddress"] = func() string {
		return gofakeit.IPv4Address()
	}
	templateFuncMap["randIPV4Address"] = func() string {
		return gofakeit.IPv4Address()
	}
	templateFuncMap["randIPV6Address"] = func() string {
		return gofakeit.IPv6Address()
	}

	return &LogGenerator{
		templateFuncMap:   templateFuncMap,
		logFieldTemplates: make(map[string]*template.Template),
	}
}

func (g *LogGenerator) SetLogFieldTemplate(field, templateStr string) error {
	tmpl, err := template.New(field).Funcs(g.templateFuncMap).Parse(templateStr)
	if err != nil {
		return err
	}
	g.logFieldTemplates[field] = tmpl
	return nil
}

type TemplateData struct {
	Hostname                    string
	Priority                    string
	Application                 string
	PID                         string
	Message                     string
	NumberZeroToThousand        string
	NumberZeroToTenThousand     string
	NumberZeroToHundredThousand string
	NumberZeroToMillion         string
	IPAddress                   string
	LocalIPAddress              string
	RemoteIPAddress             string
	Username                    string
	HTTPMethod                  string
	HTTPPath                    string
	HTTPStatusCode              string
	HTTPRequestSize             string
	HTTPResponseSize            string
	HTTPReferer                 string
	HTTPAgent                   string
	HTTPVersion                 string
	HTTPProtocol                string
	AuthUserID                  string
	BuildVersion                string
}

func (g *LogGenerator) Generate() (map[string]string, error) {
	var (
		record = make(map[string]string, len(g.logFieldTemplates))
		data   TemplateData
		buffer strings.Builder
	)

	data = TemplateData{
		Hostname:                    fmt.Sprintf("%s-%d", strings.ToLower(gofakeit.Username()), gofakeit.Number(1, 100)),
		Priority:                    strconv.Itoa(gofakeit.Number(0, 191)),
		Application:                 strings.ToLower(gofakeit.Word()),
		PID:                         strconv.Itoa(gofakeit.Number(1, 10000)),
		Message:                     gofakeit.HackerPhrase(),
		NumberZeroToThousand:        strconv.Itoa(gofakeit.Number(0, 1000)),
		NumberZeroToTenThousand:     strconv.Itoa(gofakeit.Number(0, 10000)),
		NumberZeroToHundredThousand: strconv.Itoa(gofakeit.Number(0, 100000)),
		NumberZeroToMillion:         strconv.Itoa(gofakeit.Number(0, 1000000)),
		IPAddress:                   gofakeit.IPv4Address(),
		LocalIPAddress:              gofakeit.IPv4Address(),
		RemoteIPAddress:             gofakeit.IPv4Address(),
		Username:                    strings.ToLower(gofakeit.Username()),
		HTTPMethod:                  gofakeit.HTTPMethod(),
		HTTPPath:                    randResourceURI(),
		HTTPStatusCode:              strconv.Itoa(gofakeit.StatusCode()),
		HTTPRequestSize:             strconv.Itoa(gofakeit.Number(1000, 10000)),
		HTTPResponseSize:            strconv.Itoa(gofakeit.Number(1000, 10000)),
		HTTPReferer:                 fmt.Sprintf("https://%s%s", gofakeit.DomainName(), randResourceURI()),
		HTTPAgent:                   randUserAgent(),
		HTTPVersion:                 randHTTPVersion(),
		HTTPProtocol:                randHTTPVersion(),
		AuthUserID:                  randAuthUserID(),
		BuildVersion:                randBuildVersion(),
	}

	for k, v := range g.logFieldTemplates {
		buffer.Reset()
		if err := v.Execute(&buffer, data); err != nil {
			return nil, fmt.Errorf("failed to execute template for field '%s': %w", k, err)
		}
		record[k] = buffer.String()
	}

	return record, nil
}

func randStr(strs ...string) string {
	return strs[rand.Intn(len(strs))]
}

func randBuildVersion() string {
	// Generate random build numbers
	major := rand.Intn(2000) + 1     // Assuming the major version is between 1 and 2000
	minor := rand.Intn(10)           // Assuming the minor version is between 0 and 9
	build := rand.Intn(10000000) + 1 // Assuming the build number is between 1 and 10000000
	patch := rand.Intn(100)          // Assuming the patch version is between 0 and 99
	// Format the build version
	buildVersion := fmt.Sprintf("%d.%d.%07d.%02d", major, minor, build, patch)
	return buildVersion
}

func randResourceURI() string {
	var uri string
	num := gofakeit.Number(1, 4)
	for i := 0; i < num; i++ {
		uri += "/" + url.QueryEscape(gofakeit.BS())
	}
	uri = strings.ToLower(uri)
	return uri
}

func randAuthUserID() string {
	return randStr("-", strings.ToLower(gofakeit.Username()))
}

func randHTTPVersion() string {
	return randStr("HTTP/1.0", "HTTP/1.1", "HTTP/2.0")
}

var (
	browsers         = []string{"Chrome", "Firefox", "Safari", "Edge", "Opera"}
	browserVersions  = []string{"72.0.3626.119", "65.0", "12.0.3", "44.17763.831.0", "58.0.3135.79"}
	operatingSystems = []string{"Windows NT 6.1", "Macintosh; Intel Mac OS X 10_14_3", "X11; Linux x86_64"}
	osVersions       = []string{"10.0", "6.1", "5.1"}
	engines          = map[string]string{
		"Chrome":  "Blink",
		"Firefox": "Gecko",
		"Safari":  "WebKit",
		"Edge":    "Blink",
		"Opera":   "Blink",
	}
)

func randUserAgent() string {
	browser := randStr(browsers...)
	browserVersion := randStr(browserVersions...)
	operatingSystem := randStr(operatingSystems...)
	osVersion := randStr(osVersions...)
	engine := engines[browser]
	var userAgent string
	if browser == "Safari" {
		userAgent = fmt.Sprintf(
			"Mozilla/5.0 (%s; %s) AppleWebKit/%s (KHTML, like Gecko) Version/%s Safari/%s",
			operatingSystem, osVersion, engine, browserVersion, engine)
	} else {
		userAgent = fmt.Sprintf(
			"Mozilla/5.0 (%s; %s) %s/%s (KHTML, like Gecko) %s/%s",
			operatingSystem, osVersion, engine, engine, browser, browserVersion)
	}
	return userAgent
}

func main() {
}
