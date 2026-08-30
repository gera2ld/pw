package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Item struct {
	Name        string
	Time        string
	DisplayTime string
	Size        int64
	Hash        string
}

type BuildResult struct {
	Commit string
	Items  []Item
}

const binDir = "bin"

var args = [][]string{
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
	{"linux", "amd64"},
	{"linux", "arm64"},
}

func getVersion() string {
	hash, err := exec.Command("git", "rev-parse", "--short=7", "HEAD").Output()
	if err != nil {
		log.Fatalf("Error getting commit: %s\n", err)
	}
	hashStr := strings.TrimSpace(string(hash))
	now := time.Now().UTC()
	return fmt.Sprintf("%d.%d.%d-%s", now.Year()-2000, now.Month(), now.Day(), hashStr)
}

func getItem(name string) Item {
	path := binDir + "/" + name
	fileInfo, err := os.Stat(path)
	if err != nil {
		log.Fatalf("Error reading file: %s\n", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Error reading file: %s\n", path)
	}
	sum := sha256.Sum256(data)
	return Item{
		Name:        name,
		Time:        fileInfo.ModTime().Format(time.RFC3339),
		DisplayTime: fileInfo.ModTime().Format(time.RFC1123),
		Size:        fileInfo.Size(),
		Hash:        hex.EncodeToString(sum[:]),
	}
}

func tarGzFile(src, dst, name string) {
	in, err := os.Open(src)
	if err != nil {
		log.Fatalf("Error opening file: %s\n", src)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		log.Fatalf("Error reading file info: %s\n", src)
	}
	out, err := os.Create(dst)
	if err != nil {
		log.Fatalf("Error creating file: %s\n", dst)
	}
	gw, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		log.Fatalf("Error creating gzip writer: %s\n", err)
	}
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o755,
		Size:     info.Size(),
		Typeflag: tar.TypeReg,
	}); err != nil {
		log.Fatalf("Error writing tar header: %s\n", err)
	}
	if _, err := io.Copy(tw, in); err != nil {
		log.Fatalf("Error compressing file: %s\n", err)
	}
	if err := tw.Close(); err != nil {
		log.Fatalf("Error closing tar: %s\n", err)
	}
	if err := gw.Close(); err != nil {
		log.Fatalf("Error closing gzip: %s\n", err)
	}
	if err := out.Close(); err != nil {
		log.Fatalf("Error closing file: %s\n", dst)
	}
}

func build() BuildResult {
	version := getVersion()
	log.Printf("Build version: %s\n", version)
	result := BuildResult{
		Commit: version,
	}
	for _, item := range args {
		buildOs := item[0]
		buildArch := item[1]
		suffix := ""
		if buildOs == "windows" {
			suffix = ".exe"
		}
		now := time.Now().UTC().Format(time.RFC3339)
		log.Printf("Build os=%s, arch=%s\n", buildOs, buildArch)
		name := "pw-" + buildOs + "-" + buildArch + suffix
		cmd := exec.Command(
			"go",
			"build",
			"-ldflags",
			"-s -w -X main.version="+version+" -X main.builtAt="+now+getRepoLDFlag(),
			"-trimpath",
			"-o",
			binDir+"/"+name,
			"./cmd/pw",
		)
		env := os.Environ()
		cmd.Env = append(env, "CGO_ENABLED=0", "GOOS="+buildOs, "GOARCH="+buildArch)
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		err := cmd.Run()
		if err != nil {
			log.Fatalf("Failed building os=%s, arch=%s\n", buildOs, buildArch)
		}
		tarGzFile(binDir+"/"+name, binDir+"/"+name+".tar.gz", name)
		os.Remove(binDir + "/" + name)
		result.Items = append(result.Items, getItem(name+".tar.gz"))
	}
	var sb strings.Builder
	sb.WriteString(version + "\n")
	for _, item := range result.Items {
		sb.WriteString(item.Name + " " + item.Hash + "\n")
	}
	os.WriteFile(binDir+"/version.txt", []byte(sb.String()), 0644)
	log.Printf("Wrote version to %s/version.txt\n", binDir)
	return result
}

func getRepoLDFlag() string {
	repo := os.Getenv("BUILD_REPO")
	if repo == "" {
		return ""
	}
	return " -X pw/internal/update.Repo=" + repo
}

func main() {
	build()
}
