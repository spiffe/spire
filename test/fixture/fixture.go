package fixture

import (
	"io/ioutil"
	"path/filepath"
	"runtime"
)

var (
	packageDir string
)

func init() {
	packageDir = initPackageDir()
}

func initPackageDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to obtain caller information")
	}
	return filepath.Dir(file)
}

func Path(path string) string {
	return filepath.Join(packageDir, path)
}

func Join(parts ...string) string {
	return Path(filepath.Join(parts...))
}

func Load(path string) ([]byte, error) {
	return ioutil.ReadFile(Path(path))
}
