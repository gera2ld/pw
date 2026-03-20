package main

import (
	"fmt"
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
	fileInfo, err := os.Stat(binDir + "/" + name)
	if err != nil {
		log.Fatalf("Error reading file: %s\n", binDir+"/"+name)
	}
	return Item{
		Name:        name,
		Time:        fileInfo.ModTime().Format(time.RFC3339),
		DisplayTime: fileInfo.ModTime().Format(time.RFC1123),
		Size:        fileInfo.Size(),
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
		result.Items = append(result.Items, getItem(name))
	}
	os.WriteFile(binDir+"/version.txt", []byte(version), 0644)
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
