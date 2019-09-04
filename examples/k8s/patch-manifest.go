package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

const (
	flagPrefix = "--admission-control-config-file="
	configPath = "/var/lib/spire/admission-control.yaml"
	configFlag = flagPrefix + configPath
)

func main() {
	pod := new(corev1.Pod)

	in, err := ioutil.ReadAll(os.Stdin)
	checkErr(err, "reading pod spec")

	err = yaml.Unmarshal(in, pod)
	checkErr(err, "unmarshaling pod spec")

	if len(pod.Spec.Containers) != 1 {
		bail("expecting 1 container, got %d", len(pod.Spec.Containers))
	}

	addCommand(&pod.Spec.Containers[0])
	addVolumeMount(&pod.Spec.Containers[0])
	addVolume(&pod.Spec)

	out, err := yaml.Marshal(pod)
	checkErr(err, "marshaling pod spec")

	_, err = os.Stdout.Write(out)
	checkErr(err, "writing pod spec")
}

func addCommand(container *corev1.Container) {
	for i, cmd := range container.Command {
		if strings.HasPrefix(cmd, flagPrefix) {
			container.Command[i] = configFlag
			return
		}
	}
	container.Command = append(container.Command, configFlag)
}

func addVolumeMount(container *corev1.Container) {
	volumeMount := corev1.VolumeMount{
		MountPath: "/var/lib/spire",
		Name:      "spire",
		ReadOnly:  true,
	}
	for i, m := range container.VolumeMounts {
		if m.Name == "spire" {
			container.VolumeMounts[i] = volumeMount
			return
		}
	}
	container.VolumeMounts = append(container.VolumeMounts, volumeMount)
}

func addVolume(spec *corev1.PodSpec) {
	hostPathType := corev1.HostPathDirectoryOrCreate
	volume := corev1.Volume{
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/var/lib/spire",
				Type: &hostPathType,
			},
		},
		Name: "spire",
	}
	for i, m := range spec.Volumes {
		if m.Name == "spire" {
			spec.Volumes[i] = volume
			return
		}
	}
	spec.Volumes = append(spec.Volumes, volume)
}

func checkErr(err error, reason string) {
	if err != nil {
		bail("failed %s: %v", reason, err)
	}
}

func bail(format string, args ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, args...))
	os.Exit(1)
}
