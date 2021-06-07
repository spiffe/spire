//package main
package controllers

import (
	"fmt"
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v2"
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

// type Fields struct {
// 	Provider          *Provider          `yaml:"provider,omitempty"`
// 	Region            *Region            `yaml:"region,omitempty"`
// 	WorkloadNamespace *WorkloadNamespace `yaml:"workload-namespace,omitempty"`
// 	WorkloadPodname   *WorkloadPodname   `yaml:"workload-podname,omitempty"`
// }

// type Provider struct {
// 	NodeAttestor *Attestor `yaml:"nodeAttestor"`
// }

// type Region struct {
// 	// k8s:
// 	// configMap:
// 	//   ns: kube-system
// 	//   name: cluster-info
// 	//   field: cluster-region
// 	SourceName string `yaml:"source-name"`
// 	DataType   string `yaml:"data-type"`
// }

// type WorkloadNamespace struct {
// 	WorkloadAttestor *Attestor `yaml:"workloadAttestor"`
// }

// type WorkloadPodname struct {
// 	WorkloadAttestor *Attestor `yaml:"workloadAttestor"`
// }

type Attestor struct {
	Type    string    `yaml:"type"`
	Name    string    `yaml:"name"`
	Mapping []Mapping `yaml:"mapping"`
}

type Mapping struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
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
	// if err != nil {
	// 	log.Fatalf("Error getting IdenitySchema config %v", err)
	// }

	// fields := is.Fields
	// // log.Printf("Identity provider %#v", &fields)
	// for i, field := range fields {
	// 	log.Printf("%d Field name: %s", i, field.Name)
	// 	log.Printf("%d Field Source %v", i, field.Source.Name)
	// 	att := field.Source.Attestor
	// 	if att != nil {
	// 		log.Printf("%d Field Attestor Name %v", i, att.Name)
	// 		log.Printf("%d Field Mapping %#v", i, att.Mapping)
	// 	}

	// 	cm := field.Source.ConfigMap
	// 	if cm != nil {
	// 		log.Printf("%d ConfigMap Name %s", i, cm.Name)
	// 		log.Printf("%d ConfigMap Field %s", i, cm.Field)
	// 		log.Printf("%d ConfigMap Namespace %s", i, cm.Namespace)
	// 	}

	// }

	finalId := is.getId()
	log.Printf("** Final id %v", finalId)
	log.Printf("Identity %#v", is)
	fmt.Print(&is)
}

func (is *IdentitySchema) getId() string {
	var idString string = ""
	fields := is.Fields
	// log.Printf("Identity provider %#v", &fields)
	for i, field := range fields {
		log.Printf("%d Field name: %s", i, field.Name)
		log.Printf("%d Field Source %v", i, field.Source.Name)
		idString += "/" + is.getValue(field)
	}
	log.Printf("*** ID Value: %s", idString)
	return idString
	//return makeID(r.c.TrustDomain, "k8s-workload-registrar/%s/node/%s", r.c.Cluster, nodeName)
}

func (is *IdentitySchema) getValue(field Field) string {
	log.Printf("Field name: %s", field.Name)
	log.Printf("Field Source %v", field.Source.Name)
	att := field.Source.Attestor
	if att != nil {
		log.Printf("Field Attestor Name %v", att.Name)
		log.Printf("Field Mapping %#v", att.Mapping)
		return is.getValueFromAttestor(field.Name, att)
	}

	cm := field.Source.ConfigMap
	if cm != nil {
		log.Printf("ConfigMap Name %s", cm.Name)
		log.Printf("ConfigMap Field %s", cm.Field)
		log.Printf("ConfigMap Namespace %s", cm.Namespace)
	}

	// TODO this is just a default value
	return field.Name
}

func (is *IdentitySchema) getValueFromAttestor(name string, attestor *Attestor) string {
	log.Printf("Attestor name: %s, type: %s", attestor.Name, attestor.Type)
	log.Printf("This attestor uses mapping: %#v", attestor.Mapping)

	// TODO for now, just return the field name
	return name
}

func (is *IdentitySchema) getValueFromConfgimap(name string, configmap *ConfigMap) string {
	log.Printf("ConfigMap namespace: %s, name: %s, field: %s", configmap.Namespace, configmap.Name, configmap.Field)

	// TODO for now, just return the field name
	return name
}
