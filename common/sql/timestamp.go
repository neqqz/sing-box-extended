package sql

import (
	"time"

	"github.com/huandu/go-sqlbuilder"
	E "github.com/sagernet/sing/common/exceptions"
)

const timestampFormat = "2006-01-02 15:04:05.000"

func FormatTimestamp(t time.Time) string {
	return t.UTC().Format(timestampFormat)
}

func ParseTimestamp(value string) (time.Time, error) {
	return time.ParseInLocation(timestampFormat, value, time.UTC)
}

func ParseFilterTimestamp(value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	if t, err := ParseTimestamp(value); err == nil {
		return t, nil
	}
	return time.Time{}, E.New("invalid timestamp: ", value)
}

func TimestampGreaterEqualThanFilter(field string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		t, err := ParseFilterTimestamp(value[0])
		if err != nil {
			return err
		}
		sb.Where(sb.GreaterEqualThan(field, FormatTimestamp(t)))
		return nil
	}
}

func TimestampLessEqualThanFilter(field string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		t, err := ParseFilterTimestamp(value[0])
		if err != nil {
			return err
		}
		sb.Where(sb.LessEqualThan(field, FormatTimestamp(t)))
		return nil
	}
}
