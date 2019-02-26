package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"reflect"

	"github.com/zeebo/errs"

	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getObject(ctx context.Context, typ, name string, obj v1meta.ObjectMetaAccessor, owner *Object) (bool, error) {
	if name == "" {
		return false, errors.New("must get object by non-empty name")
	}
	if err := kubectlGet(ctx, typ, name, obj); err != nil {
		if errs.Unwrap(err) == io.EOF {
			return false, nil
		}
		return false, err
	}
	if owner != nil {
		return filterObjectByOwner(obj, owner)
	}
	return true, nil
}

func getList(ctx context.Context, typ string, list v1meta.ListMetaAccessor, owner *Object) error {
	if err := kubectlGet(ctx, typ, "", list); err != nil {
		if errs.Unwrap(err) == io.EOF {
			return nil
		}
		return err
	}
	if owner != nil {
		return filterListByOwner(list, owner)
	}
	return nil
}

func kubectlGet(ctx context.Context, typ, name string, obj interface{}) error {
	args := []string{"get", typ}
	if name != "" {
		args = append(args, name, "--ignore-not-found")
	}
	return kubectlCmdJSON(ctx, obj, args...)
}

func kubectlCmdJSON(ctx context.Context, obj interface{}, args ...string) error {
	stderr := new(bytes.Buffer)
	cmd := kubectlCmd(append([]string{"-o", "json"}, args...)...)
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return errs.Wrap(err)
	}

	errch := make(chan error, 1)
	go func() {
		errch <- json.NewDecoder(stdout).Decode(obj)
	}()

	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return errs.New("%v\n%s", err, stderr.String())
		}
		return errs.Wrap(err)
	}

	select {
	case err := <-errch:
		if err != nil {
			return errs.Wrap(err)
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func kubectlStreamLogs(ctx context.Context, object string, w io.Writer) error {
	stderr := new(bytes.Buffer)
	cmd := kubectlCmd("logs", "-f", object)
	cmd.Stdout = w
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return errs.Wrap(err)
	}

	errch := make(chan error, 1)
	go func() {
		errch <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		if err := cmd.Process.Kill(); err != nil {
			Warnln("unable to kill kubectl: %v", err)
		}
		return ctx.Err()
	case err := <-errch:
		if stderr.Len() > 0 {
			return errs.New("%v\n%s", err, stderr.String())
		}
		return errs.Wrap(err)
	}
}

func kubectlRun(args ...string) error {
	stderr := new(bytes.Buffer)
	cmd := kubectlCmd(args...)
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return errs.New("%v\n%s", err, stderr.String())
		}
		return errs.Wrap(err)
	}
	return nil
}

func kubectlCmd(args ...string) *exec.Cmd {
	return exec.Command("kubectl", append([]string{"-n", NamespaceName}, args...)...)
}

func filterListByOwner(list v1meta.ListMetaAccessor, owner *Object) error {
	pv := reflect.ValueOf(list)
	if pv.Type().Kind() != reflect.Ptr {
		return errs.New("expecting pointer to list struct")
	}
	v := pv.Elem()
	if v.Type().Kind() != reflect.Struct {
		return errs.New("expecting pointer to list struct")
	}

	fv := v.FieldByName("Items")
	if fv == (reflect.Value{}) {
		return errs.New("list struct missing items field")
	}

	// create a new slice to place objects that pass the filter
	nv := reflect.New(fv.Type()).Elem()

	// iterate over each item, filtering each item by owner
	for i := 0; i < fv.Len(); i++ {
		iv := fv.Index(i)
		ok, err := filterObjectByOwner(iv.Addr().Interface(), owner)
		if err != nil {
			return err
		}
		if ok {
			nv = reflect.Append(nv, iv)
		}
	}
	fv.Set(nv)
	return nil
}

func filterObjectByOwner(obj interface{}, owner *Object) (bool, error) {
	accessor, ok := obj.(v1meta.ObjectMetaAccessor)
	if !ok {
		return false, errs.New("not an object")
	}
	for _, ownerRef := range accessor.GetObjectMeta().GetOwnerReferences() {
		if ownerRef.Kind == owner.Kind && ownerRef.Name == owner.Name {
			return true, nil
		}
	}
	return false, nil
}
