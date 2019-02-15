package main

import (
	"context"
	"encoding/json"
)

func ApplyConfig(ctx context.Context, path string) ([]Object, error) {
	var raw json.RawMessage
	if err := kubectlCmdJSON(ctx, &raw, "apply", "-f", path); err != nil {
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
