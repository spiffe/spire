package catalog

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/zeebo/errs"
)

var (
	pluginInfoType  = reflect.TypeOf((*PluginInfo)(nil)).Elem()
	fieldLoggerType = reflect.TypeOf((*logrus.FieldLogger)(nil)).Elem()
)

type PluginInfo interface {
	Name() string
	Type() string
}

type PluginName string

func (name PluginName) Name() string { return string(name) }

type catalogFiller struct {
	plugins []*pluginFiller
}

func newCatalogFiller(plugins []*LoadedPlugin) *catalogFiller {
	cf := new(catalogFiller)
	for _, plugin := range plugins {
		cf.plugins = append(cf.plugins, newPluginFiller(plugin))
	}
	return cf
}

func (cf *catalogFiller) fill(x interface{}) error {
	// assert the passed in catalog interface value is a pointer (necessary for
	// the code to modify)
	pv := reflect.ValueOf(x)
	if pv.Kind() != reflect.Ptr {
		return errs.New("expected pointer to interface or struct (got %T)", x)
	}
	ev := pv.Elem()
	switch ev.Type().Kind() {
	case reflect.Struct:
		return cf.fillStruct(ev)
	case reflect.Interface:
		return cf.fillInterface(ev)
	default:
		return errs.New("unsupported type %q", ev.Type())
	}
}

func (cf *catalogFiller) fillStruct(sv reflect.Value) error {
	// deference the catalog pointer to obtain the value and type. assert that
	// the catalog value is a struct.
	st := sv.Type()

	// traverse each field in the struct and meet the requirements from the
	// set of available plugins.
	for i := 0; i < st.NumField(); i++ {
		fv := sv.Field(i)
		ft := st.Field(i)

		if ft.PkgPath != "" {
			continue
		}

		if err := cf.fillStructField(fv, ft); err != nil {
			return errs.New("unable to set catalog field %q: %v", ft.Name, err)
		}
	}
	return nil
}

func (cf *catalogFiller) fillStructField(fv reflect.Value, ft reflect.StructField) error {
	if ft.Anonymous {
		switch ft.Type.Kind() {
		case reflect.Struct:
			return cf.fillStruct(fv)
		case reflect.Interface:
			return cf.fillInterface(fv)
		default:
			return errs.New("unsupported embedded field type %q", ft.Type)
		}
	}

	opts, err := parseFieldOpts(ft.Tag)
	if err != nil {
		return err
	}
	if opts.ignore {
		return nil
	}

	hv, err := cf.getFieldValue(ft.Type, opts.min, opts.max)
	if err != nil {
		return err
	}
	if hv != (reflect.Value{}) {
		fv.Set(hv)
	}
	return nil
}

// getFieldValue returns a filled out value for a struct field
func (cf *catalogFiller) getFieldValue(ft reflect.Type, min, max int) (reflect.Value, error) {
	switch ft.Kind() {
	// Pointer to an interface or struct (of interfaces)
	case reflect.Ptr:
		et := ft.Elem()
		if !isInterfaceOrStructOfInterfaces(et) {
			return reflect.Value{}, fmt.Errorf("pointers must be to an interface or struct (of interfaces)")
		}
		_, values, err := cf.getValues(et, 0, 1)
		if err != nil {
			return reflect.Value{}, err
		}
		if len(values) == 0 {
			return reflect.Value{}, nil
		}
		return values[0].Addr(), nil

	// Slices must be a slice of interfaces or structs (of interfaces).
	case reflect.Slice:
		et := ft.Elem()
		if !isInterfaceOrStructOfInterfaces(et) {
			return reflect.Value{}, fmt.Errorf("slices must be to an interface or struct (of interfaces)")
		}

		_, values, err := cf.getValues(et, min, max)
		if err != nil {
			return reflect.Value{}, err
		}

		s := reflect.MakeSlice(ft, 0, len(values))
		return reflect.Append(s, values...), nil

	// a map must be from a string to interface or struct (of interfaces)
	case reflect.Map:
		kt := ft.Key()
		vt := ft.Elem()
		if kt.Kind() != reflect.String {
			return reflect.Value{}, fmt.Errorf("map key type must be a string")
		}
		if !isInterfaceOrStructOfInterfaces(vt) {
			return reflect.Value{}, fmt.Errorf("map value type must be to an interface or struct (of interfaces)")
		}

		names, values, err := cf.getValues(vt, min, max)
		if err != nil {
			return reflect.Value{}, err
		}

		m := reflect.MakeMap(ft)
		for i, value := range values {
			name := names[i]
			key := reflect.ValueOf(name)
			if m.MapIndex(key) != (reflect.Value{}) {
				return reflect.Value{}, fmt.Errorf("duplicate %s plugin %q", vt.Name(), name)
			}
			m.SetMapIndex(key, value)
		}
		return m, nil

	// This represents a field that is a struct (of interfaces) or an interface
	case reflect.Struct, reflect.Interface:
		_, values, err := cf.getValues(ft, 1, 1)
		if err != nil {
			return reflect.Value{}, err
		}
		return values[0], nil
	default:
		return reflect.Value{}, fmt.Errorf("unsupported field type %q", ft)
	}
}

func (cf *catalogFiller) fillInterface(sv reflect.Value) (err error) {
	_, values, err := cf.getValues(sv.Type(), 1, 1)
	if err != nil {
		return err
	}
	sv.Set(values[0])
	return nil
}

func (cf *catalogFiller) getValues(t reflect.Type, min, max int) ([]string, []reflect.Value, error) {
	var names []string
	var values []reflect.Value
	for _, plugin := range cf.plugins {
		if value, ok := plugin.getValue(t); ok {
			names = append(names, plugin.p.Name())
			values = append(values, value)
		}
	}

	if len(values) < min {
		return nil, nil, fmt.Errorf("requires at least %d %s(s); got %d", min, t.Name(), len(values))
	}
	if max > 0 && len(values) > max {
		return nil, nil, fmt.Errorf("requires at most %d %s(s); got %d", max, t.Name(), len(values))
	}

	return names, values, nil
}

func isInterfaceOrStructOfInterfaces(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Interface:
		return true
	case reflect.Struct:
		if t.NumField() < 1 {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !isInterfaceOrStructOfInterfaces(f.Type) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

type fieldOpts struct {
	min    int
	max    int
	ignore bool
}

func parseFieldOpts(fieldTag reflect.StructTag) (_ fieldOpts, err error) {
	catalogTag := fieldTag.Get("catalog")
	if catalogTag == "" {
		return fieldOpts{}, nil
	}

	var opts fieldOpts
	maxset := false
	for _, tagValue := range strings.Split(catalogTag, ",") {
		parts := strings.SplitN(tagValue, "=", 2)
		key := parts[0]
		var value string
		if len(parts) > 1 {
			value = parts[1]
		}
		switch key {
		case "-":
			if value != "" {
				return fieldOpts{}, fmt.Errorf("not expecting key=value for catalog tag value %q", tagValue)
			}
			opts.ignore = true
		case "min":
			if value == "" {
				return fieldOpts{}, fmt.Errorf("expected key=value for catalog tag value %q", tagValue)
			}
			opts.min, err = strconv.Atoi(value)
			if err != nil {
				return fieldOpts{}, fmt.Errorf("invalid catalog tag min value %q", value)
			}
		case "max":
			if value == "" {
				return fieldOpts{}, fmt.Errorf("expected key=value for catalog tag value %q", tagValue)
			}
			opts.max, err = strconv.Atoi(value)
			if err != nil {
				return fieldOpts{}, fmt.Errorf("invalid catalog tag max value %q", value)
			}
			maxset = true
		default:
			return fieldOpts{}, fmt.Errorf("unrecognized catalog tag key %q", key)
		}
	}

	if opts.min < 0 {
		return fieldOpts{}, fmt.Errorf("catalog tag min value must be >= 0")
	}
	if maxset {
		if opts.max < 1 {
			return fieldOpts{}, fmt.Errorf("catalog tag max value must be > 0")
		}
		if opts.max < opts.min {
			return fieldOpts{}, fmt.Errorf("catalog tag max value must be >= min")
		}
	}
	return opts, nil
}

type pluginFiller struct {
	p *LoadedPlugin
}

func newPluginFiller(p *LoadedPlugin) *pluginFiller {
	return &pluginFiller{
		p: p,
	}
}

func (pf *pluginFiller) fill(x interface{}) error {
	pv := reflect.ValueOf(x)
	if pv.Kind() != reflect.Ptr {
		return errs.New("type %s must be a pointer to an interface or struct of interfaces", pv.Type().Name())
	}

	xv := pv.Elem()
	if !isInterfaceOrStructOfInterfaces(xv.Type()) {
		return errs.New("type %s must be a pointer to an interface or struct of interfaces", pv.Type().Name())
	}

	v, ok := pf.getValue(xv.Type())
	if !ok {
		return errs.New("plugin does not satisfy type %s", xv.Type())
	}
	xv.Set(v)
	return nil
}

func (pf *pluginFiller) getValue(t reflect.Type) (reflect.Value, bool) {
	switch t.Kind() {
	case reflect.Interface:
		return pf.fillInterface(t)
	case reflect.Struct:
		return pf.fillStruct(t)
	default:
		return reflect.Value{}, false
	}
}

func (pf *pluginFiller) fillInterface(t reflect.Type) (reflect.Value, bool) {
	// the PluginInfo and logrus.FieldLogger interfaces are satisfied by the
	// plugin itself
	switch t {
	case pluginInfoType:
		var pluginInfo PluginInfo = pf.p
		return reflect.ValueOf(pluginInfo), true
	case fieldLoggerType:
		var fieldLogger logrus.FieldLogger = pf.p.log
		return reflect.ValueOf(fieldLogger), true
	}

	// loop through all of the implementations. only one needs to satisfy the
	// interface.
	for _, impl := range pf.p.all {
		implValue := reflect.ValueOf(impl)

		// see if the plugin impl meets the interface directly
		if !implValue.Type().Implements(t) {
			continue
		}

		// construct a new interface value and set it with the impl.
		value := reflect.New(t).Elem()
		value.Set(implValue)
		return value, true
	}
	return reflect.Value{}, false
}

func (pf *pluginFiller) fillStruct(t reflect.Type) (reflect.Value, bool) {
	structValue := reflect.New(t).Elem()

	// each struct field (interface) must be satisfied by the plugin
	for i := 0; i < structValue.NumField(); i++ {
		fv := structValue.Field(i)
		ft := t.Field(i)

		// ignore unexported fields
		if ft.PkgPath != "" {
			continue
		}

		var fieldValue reflect.Value
		var ok bool
		switch ft.Type.Kind() {
		case reflect.Interface:
			fieldValue, ok = pf.fillInterface(ft.Type)
		case reflect.Struct:
			fieldValue, ok = pf.fillStruct(ft.Type)
		}
		if !ok {
			return reflect.Value{}, false
		}
		fv.Set(fieldValue)
	}

	return structValue, true
}
