package catalog

import (
	"errors"
	"fmt"
	"reflect"
)

type bindablePluginRepo interface {
	PluginRepo
	bindable
}

type bindableServiceRepo interface {
	ServiceRepo
	bindable
}

type bindable interface {
	bind(Facade)
}

func makeBindablePluginRepos(repos map[string]PluginRepo) (map[string]bindablePluginRepo, error) {
	bindables := make(map[string]bindablePluginRepo)
	for pluginType, repo := range repos {
		bindable, err := makeBindablePluginRepo(repo)
		if err != nil {
			return nil, err
		}
		bindables[pluginType] = bindable
	}
	return bindables, nil
}

func makeBindablePluginRepo(repo PluginRepo) (bindablePluginRepo, error) {
	binder, err := makeServiceRepoBinder(repo)
	if err != nil {
		return nil, err
	}
	return struct {
		PluginRepo
		bindable
	}{
		PluginRepo: repo,
		bindable:   binder,
	}, nil
}

func makeBindableServiceRepos(repos []ServiceRepo) ([]bindableServiceRepo, error) {
	var bindables []bindableServiceRepo
	for _, repo := range repos {
		bindable, err := makeBindableServiceRepo(repo)
		if err != nil {
			return nil, err
		}
		bindables = append(bindables, bindable)
	}
	return bindables, nil
}

func makeBindableServiceRepo(repo ServiceRepo) (bindableServiceRepo, error) {
	binder, err := makeServiceRepoBinder(repo)
	if err != nil {
		return nil, err
	}
	return struct {
		ServiceRepo
		bindable
	}{
		ServiceRepo: repo,
		bindable:    binder,
	}, nil
}

func makeServiceRepoBinder(repo ServiceRepo) (binder, error) {
	b, err := makeBinder(repo.Binder())
	if err != nil {
		return binder{}, fmt.Errorf("%T has an invalid binder: %w", repo, err)
	}
	for _, version := range repo.Versions() {
		facade := version.New()
		if err := b.canBind(facade); err != nil {
			return binder{}, fmt.Errorf("%T has an invalid binder: %w", repo, err)
		}
	}
	return b, nil
}

type binder struct {
	fnv reflect.Value
}

func makeBinder(fn any) (binder, error) {
	fnv := reflect.ValueOf(fn)
	if fnv == (reflect.Value{}) {
		return binder{}, errors.New("binder cannot be nil")
	}
	fnt := fnv.Type()
	switch {
	case fnt.Kind() != reflect.Func:
		return binder{}, errors.New("binder is not a function")
	case fnt.NumIn() != 1:
		return binder{}, errors.New("binder must accept one argument")
	}
	return binder{fnv: fnv}, nil
}

func (b binder) canBind(facade Facade) error {
	facadeType := reflect.TypeOf(facade)
	if in := b.fnv.Type().In(0); !facadeType.AssignableTo(in) {
		return fmt.Errorf("facade %T is not assignable to argument %s", facade, in)
	}
	return nil
}

func (b binder) bind(facade Facade) {
	b.fnv.Call([]reflect.Value{reflect.ValueOf(facade)})
}
