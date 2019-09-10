package sql

import (
	"database/sql/driver"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"time"
)

type MigrationLogger struct {
	outfile io.Writer
}

func (logger *MigrationLogger) Print(v ...interface{}) {
	if v[0] == "sql" && len(v) > 1 {
		logger.outfile.Write([]byte(format(v...) + "\n"))
	}
}

func (logger *MigrationLogger) SetOutput(out io.Writer) {
	logger.outfile = out
}

// This is a reduced version of gorm's LogFormatter - https://github.com/jinzhu/gorm/blob/master/logger.go
func format(values ...interface{}) string {
	sqlRegexp := regexp.MustCompile(`\?`)
	numericPlaceHolderRegexp := regexp.MustCompile(`\$\d+`)

	var (
		sql             string
		formattedValues []string
	)

	for _, value := range values[4].([]interface{}) {
		indirectValue := reflect.Indirect(reflect.ValueOf(value))
		if indirectValue.IsValid() {
			value = indirectValue.Interface()
			if t, ok := value.(time.Time); ok {
				formattedValues = append(formattedValues, fmt.Sprintf("'%v'", t.Format("2006-01-02 15:04:05")))
			} else if b, ok := value.([]byte); ok {
				formattedValues = append(formattedValues, fmt.Sprintf("'%v'", string(b)))
			} else if r, ok := value.(driver.Valuer); ok {
				if value, err := r.Value(); err == nil && value != nil {
					formattedValues = append(formattedValues, fmt.Sprintf("'%v'", value))
				} else {
					formattedValues = append(formattedValues, "NULL")
				}
			} else {
				switch value.(type) {
				case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, bool:
					formattedValues = append(formattedValues, fmt.Sprintf("%v", value))
				default:
					formattedValues = append(formattedValues, fmt.Sprintf("'%v'", value))
				}
			}
		} else {
			formattedValues = append(formattedValues, "NULL")
		}
	}

	// differentiate between $n placeholders or else treat like ?
	if numericPlaceHolderRegexp.MatchString(values[3].(string)) {
		sql = values[3].(string)
		for index, value := range formattedValues {
			placeholder := fmt.Sprintf(`\$%d([^\d]|$)`, index+1)
			sql = regexp.MustCompile(placeholder).ReplaceAllString(sql, value+"$1")
		}
	} else {
		formattedValuesLength := len(formattedValues)
		for index, value := range sqlRegexp.Split(values[3].(string), -1) {
			sql += value
			if index < formattedValuesLength {
				sql += formattedValues[index]
			}
		}
	}
	if sql[len(sql)-1] == ';' {
		return sql
	}
	return sql + ";"
}
