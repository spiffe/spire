package qb

type literal struct {
	value       string
	singleQuote bool
}

func Literal(value string) literal {
	return literal{value: value}
}

func CqlFunction(value string) literal {
	return literal{value: value}
}

func StringLiteral(value string) literal {
	return literal{value: value, singleQuote: true}
}
