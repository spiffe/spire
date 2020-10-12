package api

type CallCounter interface {
	AddLabel(name, value string)
}
