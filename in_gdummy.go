package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit"
	"github.com/calyptia/plugin"
	"github.com/calyptia/plugin/metric"
)

func init() {
	plugin.RegisterInput("gdummy", "dummy GO!", &gdummyPlugin{})
}

type gdummyPlugin struct {
	counterSuccess metric.Counter
	counterFailure metric.Counter
	log            plugin.Logger
	gen            dataGen
	dummyMsg       map[string]string
	rate           time.Duration
}

type dataGen uint

const (
	genDummy dataGen = iota
	genSyslogRFC3164
	genSyslogRFC5424
	genNginx
	genApacheCommon
	// TODO: apache_combined, apache_error (see https://github.com/mingrammer/flog/blob/main/log.go)
	genCrowdstrikeFalconDataReplicator
)

func (plug *gdummyPlugin) Init(ctx context.Context, fbit *plugin.Fluentbit) error {
	plug.counterSuccess = fbit.Metrics.NewCounter("operation_succeeded_total", "Total number of succeeded operations", "gdummy")
	plug.counterFailure = fbit.Metrics.NewCounter("operation_failed_total", "Total number of failed operations", "gdummy")
	plug.log = fbit.Logger

	if msg := fbit.Conf.String("dummy"); msg != "" {
		if err := json.Unmarshal([]byte(msg), &plug.dummyMsg); err != nil {
			return err
		}
	}

	switch fbit.Conf.String("datagen") {
	case "":
		fallthrough
	case "dummy":
		plug.gen = genDummy
		if plug.dummyMsg == nil {
			return errors.New("invalid config: 'dummy' not set with datagen=dummy")
		}
	case "syslog":
		fallthrough
	case "syslog_rfc3164":
		plug.gen = genSyslogRFC3164
	case "syslog_rfc5424":
		plug.gen = genSyslogRFC5424
	case "nginx":
		plug.gen = genNginx
	case "apache":
		fallthrough
	case "apache_common":
		plug.gen = genApacheCommon
	case "crowdstrike_falcon_data_replicator":
		plug.gen = genCrowdstrikeFalconDataReplicator
	default:
		return fmt.Errorf("invalid config: 'datagen' unrecognized value '%s'", fbit.Conf.String("datagen"))
	}

	plug.rate = time.Second
	rateStr := fbit.Conf.String("rate")
	if rateStr != "" {
		rateFloat, err := strconv.ParseFloat(rateStr, 64)
		if err != nil {
			return err
		}
		rateNanosFloat := rateFloat * float64(time.Second)
		plug.rate = time.Duration(rateNanosFloat)
	}

	return nil
}

func (plug gdummyPlugin) Collect(ctx context.Context, ch chan<- plugin.Message) error {
	tick := time.NewTicker(plug.rate)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			if err != nil && !errors.Is(err, context.Canceled) {
				plug.counterFailure.Add(1)
				plug.log.Error("[gdummy] operation failed")

				return err
			}

			return nil
		case <-tick.C:
			plug.counterSuccess.Add(1)
			plug.log.Debug("[gdummy] operation succeeded")

			switch plug.gen {
			case genDummy:
				ch <- plugin.Message{
					Time:   time.Now(),
					Record: plug.dummyMsg,
				}
			case genSyslogRFC3164:
				ch <- plugin.Message{
					Time: time.Now(),
					Record: map[string]string{
						"priority":    strconv.Itoa(gofakeit.Number(0, 191)),
						"hostname":    strings.ToLower(gofakeit.Username()),
						"application": gofakeit.Word(),
						"pid":         strconv.Itoa(gofakeit.Number(1, 10000)),
						"message":     gofakeit.HackerPhrase(),
					},
				}
			case genSyslogRFC5424:
				ch <- plugin.Message{
					Time: time.Now(),
					Record: map[string]string{
						"priority":        strconv.Itoa(gofakeit.Number(0, 191)),
						"version ":        strconv.Itoa(gofakeit.Number(1, 3)),
						"hostname":        gofakeit.DomainName(),
						"application":     gofakeit.Word(),
						"pid":             strconv.Itoa(gofakeit.Number(1, 10000)),
						"message-id":      strconv.Itoa(gofakeit.Number(1, 1000)),
						"structured-data": "-", // TODO: structured data
						"message":         gofakeit.HackerPhrase(),
					},
				}
			case genNginx:
				ch <- plugin.Message{
					Time: time.Now(),
					Record: map[string]string{
						"remote":  gofakeit.IPv4Address(),
						"host":    gofakeit.DomainName(),
						"user":    strings.ToLower(gofakeit.Username()),
						"method":  gofakeit.HTTPMethod(),
						"path":    randResourceURI(),
						"code":    strconv.Itoa(gofakeit.StatusCode()),
						"size":    strconv.Itoa(gofakeit.Number(1000, 10000)),
						"referer": fmt.Sprintf("https://%s%s", gofakeit.DomainName(), randResourceURI()),
						"agent":   randUserAgent(),
					},
				}
			case genApacheCommon:
				ch <- plugin.Message{
					Time: time.Now(),
					Record: map[string]string{
						"host":            gofakeit.IPv4Address(),
						"user-identifier": strings.ToLower(gofakeit.Username()),
						"auth-user-id":    randAuthUserID(),
						"method":          gofakeit.HTTPMethod(),
						"request":         randResourceURI(),
						"protocol":        randHTTPVersion(),
						"response-code":   strconv.Itoa(gofakeit.StatusCode()),
						"bytes":           strconv.Itoa(gofakeit.Number(0, 30000)),
					},
				}
			case genCrowdstrikeFalconDataReplicator:
				connDir := strconv.Itoa(gofakeit.Number(0, 1))
				ch <- plugin.Message{
					Time: time.Now(),
					Record: map[string]string{
						"LocalAddressIP4":            gofakeit.IPv4Address(),
						"event_simpleName":           "NetworkConnectIP4",    // TODO: more event types
						"name":                       "NetworkConnectIP4V10", // TODO: more event types
						"ConfigStateHash":            strconv.Itoa(gofakeit.Number(65535, 4294967295)),
						"ConnectionFlags":            strconv.Itoa(gofakeit.Number(0, 8)),
						"ContextProcessId":           strconv.Itoa(gofakeit.Number(128, 65535)),
						"RemotePort":                 strconv.Itoa(gofakeit.Number(0, 65535)),
						"aip":                        gofakeit.IPv4Address(),
						"ConfigBuild":                randBuildVersion(),
						"event_platform":             randStr("Win", "Linux", "Mac"),
						"LocalPort":                  strconv.Itoa(gofakeit.Number(0, 65535)),
						"Entitlements":               strconv.Itoa(gofakeit.Number(0, 32)),
						"EventOrigin":                strconv.Itoa(gofakeit.Number(0, 4)),
						"id":                         strings.ToLower(gofakeit.UUID()),
						"Protocol":                   strconv.Itoa(gofakeit.Number(2, 8)),
						"EffectiveTransmissionClass": strconv.Itoa(gofakeit.Number(2, 8)),
						"aid":                        strings.ReplaceAll(strings.ToLower(gofakeit.UUID()), "-", ""),
						"RemoteAddressIP4":           gofakeit.IPv4Address(),
						"ConnectionDirection":        connDir,
						"InContext":                  connDir,
						"cid":                        strings.ReplaceAll(strings.ToLower(gofakeit.UUID()), "-", ""),
					},
				}
			default:
				return fmt.Errorf("misconfigured plugin: unknown data generator %d", plug.gen)
			}
		}
	}
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
