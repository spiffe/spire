package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/zeebo/errs"
)

var (
	// multi-line, ungreedy match for a YAML configuration line for a non-local spire-* image
	reSpireImage = regexp.MustCompile(`(?mU)^(\s*-?\s*image:\s*)gcr.io/spiffe-io/(spire-.+)(?::.*)?$`)
)

func ApplyConfig(ctx context.Context, path string, useLocalImage bool) ([]Object, error) {
	// read the config file in so we can replace the image
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	if useLocalImage {
		configBytes = replaceSpireImageWithLocal(configBytes)
		fmt.Println("APPLYING:\n", string(configBytes))
	}

	var raw json.RawMessage
	if err := kubectlCmdJSON(ctx, bytes.NewReader(configBytes), &raw, "apply", "-f", "-"); err != nil {
		return nil, err
	}

	type objectJSON struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name string `json:"name"`
		}
	}

	output := struct {
		objectJSON
		Items []json.RawMessage `json:"items"`
	}{}

	if err := json.Unmarshal(raw, &output); err != nil {
		return nil, err
	}

	var objects []Object
	if output.Kind == "List" {
		for _, item := range output.Items {
			object := new(objectJSON)
			if err := json.Unmarshal(item, &object); err != nil {
				return nil, err
			}
			objects = append(objects, Object{
				Kind: object.Kind,
				Name: object.Metadata.Name,
			})
		}
	} else {
		objects = append(objects, Object{
			Kind: output.Kind,
			Name: output.Metadata.Name,
		})
	}

	return objects, nil
}

func replaceSpireImageWithLocal(configBytes []byte) []byte {
	return reSpireImage.ReplaceAll(configBytes, []byte("$1$2:latest-local"))
}
