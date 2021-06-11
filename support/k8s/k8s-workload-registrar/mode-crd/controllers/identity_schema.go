//package main
package controllers

import (
	"fmt"
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type IdentitySchema struct {
	Version string  `yaml:"version"`
	Fields  []Field `yaml:"fields"`
}

type Field struct {
	Name   string  `yaml:"name"`
	Source *Source `yaml:"source"`
}

type Source struct {
	Name      string     `yaml:"name"`
	Attestor  *Attestor  `yaml:"attestor,omitempty"`
	ConfigMap *ConfigMap `yaml:"configMap,omitempty"`
}

type ConfigMap struct {
	Namespace string `yaml:"ns"`
	Name      string `yaml:"name"`
	Field     string `yaml:"field"`
}

type Attestor struct {
	Group   string    `yaml:"group"`
	Mapping []Mapping `yaml:"mapping"`
}

type Mapping struct {
	Type  string `yaml:"type"`
	Field string `yaml:"field"`
}

func (is *IdentitySchema) loadConfig(fileName string) (*IdentitySchema, error) {

	log.Print("before read")
	yamlFile, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Printf("Error reading yaml file %s:  %v ", fileName, err)
		return is, err
	}
	log.Print("after read")

	err = yaml.Unmarshal(yamlFile, is)
	if err != nil {
		//log.Fatalf("Unmarshal: %v", err)
		log.Printf("Error processing YAML file %v", err)
		return is, err
	}

	return is, nil
}

func main() {
	var is IdentitySchema

	// if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {

	if _, err := is.loadConfig("/tmp/identity-schema.yaml"); err != nil {
		log.Fatalf("Error getting IdenitySchema config %v", err)
	}

	// Set up pod:
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			ServiceAccountName: "podServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "podNamespace",
			Labels:      map[string]string{},
			Annotations: map[string]string{},
		},
	}
	// if testCase.configLabel != "" && testCase.podLabel != "" {
	// 	pod.Labels[testCase.configLabel] = testCase.podLabel
	// }
	// if testCase.configAnnotation != "" && testCase.podAnnotation != "" {
	// 	pod.Annotations[testCase.configAnnotation] = testCase.podAnnotation
	// }

	// Test:
	//spiffeID := c.podSpiffeID(pod)

	finalId := is.getId(pod)
	log.Printf("** Final id %v", finalId)
	log.Printf("Identity %#v", is)
	fmt.Print(&is)
}

func (is *IdentitySchema) getId(pod *corev1.Pod) string {

	// log.Printf("Processing Pod %#v", pod)

	var idString string = ""
	fields := is.Fields
	for i, field := range fields {
		log.Printf("%d Field name: %s", i, field.Name)
		log.Printf("%d Field source: %v", i, field.Source.Name)
		idString += "/" + is.getValue(pod, field)
	}
	log.Printf("ID Value: %s", idString)
	return idString
}

func (is *IdentitySchema) getValue(pod *corev1.Pod, field Field) string {
	att := field.Source.Attestor
	if att != nil {
		log.Printf("* Field Attestor Group Name: %v", att.Group)
		return is.getValueFromAttestor(pod, field.Name, att)
	}

	cm := field.Source.ConfigMap
	if cm != nil {
		log.Printf("* ConfigMap Name %s", cm.Name)
		log.Printf("* ConfigMap Field %s", cm.Field)
		log.Printf("* ConfigMap Namespace %s", cm.Namespace)
	}

	// TODO for now if value unknown, just return the field name
	return field.Name
}

func (is *IdentitySchema) getValueFromAttestor(pod *corev1.Pod, name string, attestor *Attestor) string {
	// log.Printf("** Attestor group: %s", attestor.Group)
	// log.Printf("** This attestor uses mapping: %#v", attestor.Mapping)

	switch attestor.Group {
	case "nodeAttestor":
		log.Print("** Processing nodeAttestor")
		return "value-from-node-Attestor"
	case "workloadAttestor":
		return getValueFromWorkloadAttestor(pod, attestor.Mapping)
	default:
		log.Print("** Unknown attestor name")
	}
	// TODO for now if value unknown, just return the field name
	return name
}

func (is *IdentitySchema) getValueFromConfgimap(name string, configmap *ConfigMap) string {
	log.Printf("** ConfigMap namespace: %s, name: %s, field: %s", configmap.Namespace, configmap.Name, configmap.Field)

	// TODO for now, just return the field name
	return name
}

func getValueFromWorkloadAttestor(pod *corev1.Pod, mapping []Mapping) string {

	for _, field := range mapping {

		//log.Printf("*** %d processing field: %#v", i, field)

		switch field.Type {
		case "k8s":
			switch field.Field {
			case "sa":
				return pod.Spec.ServiceAccountName
			case "ns":
				return pod.Namespace
			case "pod-name":
				return pod.Name
			case "pod-uid":
				return string(pod.UID)
			default:
				log.Printf("*** Unknown field for k8s attestor: %s", field.Field)
			}
		case "xxx":
			log.Printf("*** Processing xxx attestor")
		default:
			log.Printf("*** Unknown workload attestor type: %s", field.Type)
		}

	}
	return "***Error"
}
