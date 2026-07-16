package sql

import (
	"encoding/json"
	"slices"
	"strconv"

	"github.com/huandu/go-sqlbuilder"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
)

type Filter func(sb *sqlbuilder.SelectBuilder, value []string) error

func EqualFilter(field string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		sb.Where(sb.Equal(field, value[0]))
		return nil
	}
}

func EqualOrNullFilter(field string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		sb.Where(sb.Or(sb.Equal(field, value[0]), sb.IsNull(field)))
		return nil
	}
}

func GreaterThanFilter(field string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		sb.Where(sb.GreaterThan(field, value[0]))
		return nil
	}
}

func LessThanFilter(field string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		sb.Where(sb.LessThan(field, value[0]))
		return nil
	}
}

func GreaterEqualThanFilter(field string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		sb.Where(sb.GreaterEqualThan(field, value[0]))
		return nil
	}
}

func LessEqualThanFilter(field string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		sb.Where(sb.LessEqualThan(field, value[0]))
		return nil
	}
}

func SpeedGreaterEqualThanFilter(field string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		bytesSpeed, err := json.Marshal(value[0])
		if err != nil {
			return err
		}
		speed := &byteformats.NetworkBytesCompat{}
		err = speed.UnmarshalJSON(bytesSpeed)
		if err != nil {
			return err
		}
		sb.Where(sb.GreaterEqualThan(field, speed.Value()))
		return nil
	}
}

func SpeedLessEqualThanFilter(field string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		bytesSpeed, err := json.Marshal(value[0])
		if err != nil {
			return err
		}
		speed := &byteformats.NetworkBytesCompat{}
		err = speed.UnmarshalJSON(bytesSpeed)
		if err != nil {
			return err
		}
		sb.Where(sb.LessEqualThan(field, speed.Value()))
		return nil
	}
}

func ExistsAndWhereInFilter(subqueryFactory func() *sqlbuilder.SelectBuilder, field string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		values := make([]interface{}, len(value))
		for i, v := range value {
			values[i] = v
		}
		subquery := subqueryFactory()
		subquery.Where(subquery.In(field, values...))
		sb.Where(sb.Exists(subquery))
		return nil
	}
}

func InFilter(field string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		if len(value) == 0 {
			return nil
		}
		values := make([]interface{}, len(value))
		for i, v := range value {
			values[i] = v
		}
		sb.Where(sb.In(field, values...))
		return nil
	}
}

func SortAscFilter(columns []string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		column, err := isValidSortColumn(value[0], columns)
		if err != nil {
			return err
		}
		sb.OrderByAsc(column)
		return nil
	}
}

func SortDescFilter(columns []string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		column, err := isValidSortColumn(value[0], columns)
		if err != nil {
			return err
		}
		sb.OrderByDesc(column)
		return nil
	}
}

func ReplacedSortAscFilter(replace map[string]string, columns []string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		column, ok := replace[value[0]]
		if !ok {
			column = value[0]
		}
		column, err := isValidSortColumn(column, columns)
		if err != nil {
			return err
		}
		sb.OrderByAsc(column)
		return nil
	}
}

func ReplacedSortDescFilter(replace map[string]string, columns []string) Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		column, ok := replace[value[0]]
		if !ok {
			column = value[0]
		}
		column, err := isValidSortColumn(column, columns)
		if err != nil {
			return err
		}
		sb.OrderByDesc(column)
		return nil
	}
}

func LimitFilter() Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		limit, err := strconv.Atoi(value[0])
		if err != nil {
			return err
		}
		sb.Limit(limit)
		return nil
	}
}

func OffsetFilter() Filter {
	return func(sb *sqlbuilder.SelectBuilder, value []string) error {
		offset, err := strconv.Atoi(value[0])
		if err != nil {
			return err
		}
		sb.Offset(offset)
		return nil
	}
}

func isValidSortColumn(column string, columns []string) (string, error) {
	if slices.Contains(columns, column) {
		return column, nil
	}
	return "", E.New("invalid sort column \"", column, "\"")
}
