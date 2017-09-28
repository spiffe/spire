package certs

import (
	"encoding/pem"
	"io/ioutil"
	"path"
	"runtime"
)

func getBytesFromPem(fileName string) []byte {
	_, file, _, _ := runtime.Caller(1)

	pemFile, _ := ioutil.ReadFile(path.Join(path.Dir(file), fileName))
	decodedFile, _ := pem.Decode(pemFile)
	return decodedFile.Bytes
}

func GetTestBaseSVID() []byte {
	return getBytesFromPem("baseSVID.pem")
}

func GetTestBlogCSR() []byte {
	return getBytesFromPem("blogCSR.pem")
}

func GetTestBlogSVID() []byte {
	return getBytesFromPem("blogSVID.pem")
}
