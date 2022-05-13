package checktypes

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/adevinta/vulcan-agent/log"
)

const modifTimeLabel = "last_modified_file"

// Code stores a directory path containing the definition of a checktype.
type Code string

// ParseCode returns the chekcktype represented in a dir as code. if the input
// parameter is not an url pointing to the code of a checktype, it returns
// false in the second return value. An url is considered to point to the code
// of a checktype if it uses the schema "code".
func ParseCode(u string) (Code, bool) {
	url, err := url.Parse(u)
	if err != nil {
		return Code(""), false
	}
	if url.Scheme != "code" {
		return Code(""), false
	}
	return Code(strings.TrimPrefix(u, "code://")), true
}

// Build builds the checktype defined in a directory. It builds the binary and
// the docker image of the checktype and returns the name of the docker image
// built.
func (c Code) Build(logger log.Logger) (string, error) {
	modified, err := c.isModified(logger)
	if err != nil {
		return "", err
	}
	if !modified {
		logger.Infof("No changes in checktype in dir %s, reusing image %s", string(c), c.imageName())
		return c.imageName(), nil
	}
	logger.Infof("Compiling checktype in dir %s", c)
	dir := string(c)
	// Run go build in the checktype dir.
	if err := goBuildDir(dir); err != nil {
		return "", err
	}
	// Build a Tar file with the docker image contents.
	logger.Infof("Building image for checktype in dir %s", dir)
	contents, err := buildTarFromDir(dir)
	if err != nil {
		return "", err
	}
	logger.Debugf("Tar file for checktype in dir %s built", dir)
	modif, err := c.lastModified(logger)
	if err != nil {
		return "", err
	}
	t := modif.Format(time.RFC822)
	logger.Debugf("Last modified time for checktype in dir %s is %s", dir, t)
	labels := map[string]string{modifTimeLabel: t}
	image := c.imageName()
	r, err := buildDockerdImage(contents, []string{image}, labels)
	if err != nil {
		return "", err
	}
	logger.Infof("Docker image built: %s", image)
	logger.Debugf("Docker image build log:\n%s", r)
	return image, nil
}

func (c Code) isModified(logger log.Logger) (bool, error) {
	labels, err := imageInfo(c.imageName())
	if err != nil {
		return false, err
	}
	imageTimeS, ok := labels[modifTimeLabel]
	if !ok {
		logger.Infof("Image %s is does not contain the label %s", c.imageName(), modifTimeLabel)
		return true, nil
	}
	_, err = time.Parse(time.RFC822, imageTimeS)
	if err != nil {
		logger.Infof("invalid time, %+w defined in the label %s of the image %s", err, modifTimeLabel, c.imageName())
		return true, nil
	}
	dirTime, err := c.lastModified(logger)
	if err != nil {
		err := fmt.Errorf("error: %+w, getting the last modification time for the checktype in %s", err, string(c))
		return false, err
	}
	dirTimeS := dirTime.Format(time.RFC822)
	logger.Debugf("Last modified time in dir %s: %s, image time: %s ", c, imageTimeS, dirTimeS)
	modified := dirTimeS != imageTimeS
	return modified, nil
}

func (c Code) lastModified(logger log.Logger) (time.Time, error) {
	dir := string(c)
	var latest *time.Time
	logger.Debugf("Getting the last modified file in dir %s", c)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		logger.Debugf("Visiting path %s", path)
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		modtime := info.ModTime()
		if latest == nil || modtime.After(*latest) {
			latest = &modtime
		}
		return nil
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("error walking through the dir %s", dir)
	}
	if latest == nil {
		return time.Time{}, fmt.Errorf("the dir %s is empty", dir)
	}
	return *latest, nil
}

func (c Code) imageName() string {
	dir := string(c)
	image := path.Base(dir)
	return fmt.Sprintf("%s-%s", image, "local")
}

func goBuildDir(dir string) error {
	args := []string{"build", "-a", "-ldflags", "-extldflags -static", "."}
	cmd := exec.Command("go", args...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "GOOS=linux", "CGO_ENABLED=0")
	cmd.Dir = dir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func buildTarFromDir(dirPath string) (*bytes.Buffer, error) {
	dir, err := os.Open(path.Clean(dirPath))
	if err != nil {
		return nil, err
	}
	defer dir.Close() // nolint: errcheck

	files, err := dir.Readdir(0)
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	tarfileWriter := tar.NewWriter(&output)
	defer tarfileWriter.Close() // nolint: errcheck

	err = addDir(dirPath, "", tarfileWriter, files)
	return &output, err
}

func addDir(sourceDir string, currentPath string, writer *tar.Writer, finfo []os.FileInfo) error {
	for _, file := range finfo {
		tarPath := path.Join(currentPath, file.Name())
		// If file is a dir we recurse.
		if file.IsDir() {
			absPath := path.Join(sourceDir, tarPath)
			dir, err := os.Open(absPath)
			if err != nil {
				return err
			}

			files, err := dir.Readdir(0)
			if err != nil {
				return err
			}

			err = addDir(sourceDir, tarPath, writer, files)
			if err != nil {
				return err
			}
			continue
		}
		// File is not a dir, add to the the Tar.
		h, err := tar.FileInfoHeader(file, tarPath)
		if err != nil {
			return err
		}

		h.Name = tarPath
		if err = writer.WriteHeader(h); err != nil {
			return err
		}

		absFilePath := path.Join(sourceDir, tarPath)

		var content []byte
		content, err = ioutil.ReadFile(absFilePath)
		if err != nil {
			return err
		}

		if _, err = writer.Write(content); err != nil {
			return err
		}
	}
	return nil
}
