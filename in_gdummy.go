package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

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
	template       *LogGenerator
	rate           time.Duration
}

type dataGen uint

const (
	genDummy dataGen = iota
	genTemplate
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
	case "template":
		plug.gen = genTemplate
		fieldsStr := fbit.Conf.String("fields")
		if fieldsStr == "" {
			return errors.New("invalid config: 'fields' not set with datagen=template")
		}
		fieldsSeparated := strings.Split(fieldsStr, ",")
		fields := make([]string, 0, len(fieldsSeparated))
		for _, field := range fieldsSeparated {
			field = strings.TrimSpace(field)
			if field != "" {
				fields = append(fields, field)
			}
		}
		if len(fields) == 0 {
			return errors.New("invalid config: 'fields' list is empty with datagen=template")
		}

		plug.template = NewLogGenerator()
		for _, field := range fields {
			fieldValue := fbit.Conf.String(field)
			if fieldValue == "" {
				return fmt.Errorf("invalid config: field '%s' not set with datagen=template and field in fields list", field)
			}
			plug.template.SetLogFieldTemplate(field, fieldValue)
		}
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
			case genTemplate:
				record, err := plug.template.Generate()
				if err != nil {
					return err
				}

				ch <- plugin.Message{
					Time:   time.Now(),
					Record: record,
				}
			default:
				return fmt.Errorf("misconfigured plugin: unknown data generator %d", plug.gen)
			}
		}
	}
}
