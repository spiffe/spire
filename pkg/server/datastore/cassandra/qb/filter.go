package qb

type Operator string

const (
	EqualOperator    Operator = "="
	InOperator       Operator = "IN"
	ContainsOperator Operator = "CONTAINS"
	NeqOperator      Operator = "!="
	LtOperator       Operator = "<"
	GtOperator       Operator = ">"
	LteOperator      Operator = "<="
	GteOperator      Operator = ">="
)

type filterTerm struct {
	column     string
	operator   Operator
	value      any
	values     []any
	deepValues [][]any
}

func Equals(value any) filterTerm {
	return filterTerm{
		operator: EqualOperator,
		value:    value,
	}
}

func In(values ...any) filterTerm {
	return filterTerm{
		operator: InOperator,
		values:   values,
	}
}

func CollectionIn(values ...[]any) filterTerm {
	return filterTerm{
		operator:   InOperator,
		deepValues: values,
	}
}

func Contains(value any) filterTerm {
	return filterTerm{
		operator: ContainsOperator,
		value:    value,
	}
}

func LessThan(value any) filterTerm {
	return filterTerm{
		operator: LtOperator,
		value:    value,
	}
}

func GreaterThan(value any) filterTerm {
	return filterTerm{
		operator: GtOperator,
		value:    value,
	}
}

func LessThanEqual(value any) filterTerm {
	return filterTerm{
		operator: LtOperator,
		value:    value,
	}
}

func GreaterThanEqual(value any) filterTerm {
	return filterTerm{
		operator: GtOperator,
		value:    value,
	}
}
