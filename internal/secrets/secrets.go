package secrets

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"pw/internal/config"
	"pw/internal/filehandler"

	gonanoid "github.com/matoous/go-nanoid/v2"
	"gopkg.in/yaml.v3"
)

type Secret struct {
	Data    map[string]any
	Payload string
}

type SecretManager struct {
	Config      *config.ConfigType
	UserConfig  *config.UserConfigType
	Filehandler *filehandler.FileHandler
	index       *map[string]string
}

type Vars struct {
	Local map[string]string
	Env   map[string]string
}

func NewSecretManager(config *config.ConfigType, userConfig *config.UserConfigType, filehandler *filehandler.FileHandler) *SecretManager {
	return &SecretManager{Config: config, UserConfig: userConfig, Filehandler: filehandler}
}

func (d *SecretManager) GetFilePath(path string) string {
	if strings.HasPrefix(path, d.Config.DataDir+"/") {
		return path + d.Config.EnvSuffix
	}
	return path
}

func (d *SecretManager) SanitizeID(id string) string {
	re := regexp.MustCompile(`[^\w+\-/@.]`)
	return re.ReplaceAllString(id, "-")
}

func (d *SecretManager) ParseRawValue(value string) (*Secret, error) {
	lines := strings.Split(value, "\n")

	i := indexOf(lines, "---", 0)

	var yamlContent string
	if i >= 0 {
		yamlContent = strings.Join(lines[:i], "\n")
	} else {
		yamlContent = value
	}

	data := make(map[string]any)
	if err := yaml.Unmarshal([]byte(yamlContent), &data); err != nil {
		return nil, errors.New("invalid YAML: " + err.Error())
	}

	id, ok := data["__id"].(string)
	if !ok || id == "" {
		return nil, errors.New("invalid: missing or invalid '__id'")
	}

	payload := ""
	if i >= 0 && i < len(lines)-1 {
		payload = strings.Join(lines[i+1:], "\n")
	}

	return &Secret{
		Data:    data,
		Payload: payload,
	}, nil
}

func indexOf(lines []string, target string, offset int) int {
	for i := offset; i < len(lines); i++ {
		if lines[i] == target {
			return i
		}
	}
	return -1
}

func (d *SecretManager) FormatValue(value *Secret) (string, error) {
	if value == nil {
		return "", errors.New("value is nil")
	}

	output := ""

	data, err := yaml.Marshal(value.Data)
	if err != nil {
		return "", errors.New("failed to marshal data: " + err.Error())
	}
	output += string(data)

	if value.Payload != "" {
		output += "\n---\n" + value.Payload
	}

	return output, nil
}

func (d *SecretManager) EncryptData(data string) (string, error) {
	if len(d.UserConfig.Data.Recipients) == 0 {
		return "", errors.New("no recipient is added")
	}

	args := []string{"-a"}
	for _, recipient := range d.UserConfig.Data.Recipients {
		args = append(args, "-r", recipient)
	}

	cmd := exec.Command("age", args...)
	cmd.Stdin = strings.NewReader(data)

	output, err := cmd.Output()
	if err != nil {
		return "", errors.New("failed to encrypt data: " + err.Error())
	}

	return string(output), nil
}

func (d *SecretManager) DecryptData(data string) (string, error) {
	if d.Config.Identities == "" {
		return "", errors.New("no identities file provided")
	}

	args := []string{"--decrypt", "-i", d.Config.Identities}

	cmd := exec.Command("age", args...)
	cmd.Stdin = strings.NewReader(data)

	output, err := cmd.Output()
	if err != nil {
		return "", errors.New("failed to decrypt data: " + err.Error())
	}

	return string(output), nil
}

func (d *SecretManager) LoadValue(encrypted string) (*Secret, error) {
	value, err := d.DecryptData(encrypted)
	if err != nil {
		return nil, errors.New("failed to decrypt data: " + err.Error())
	}
	dynamicEnvValue, err := d.ParseRawValue(value)
	return dynamicEnvValue, err
}

func (d *SecretManager) ListSecretFiles(prefix string) ([]string, error) {
	files, err := d.Filehandler.ListFiles(filepath.Join(d.Config.DataDir, prefix), d.Config.DataDir)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(files))
	for _, file := range files {
		file = strings.ReplaceAll(file, "\\", "/")
		result = append(result, file)
	}
	return result, nil
}

func (d *SecretManager) ListItems(prefix string) map[string]*Secret {
	secrets := make(map[string]*Secret)
	files, err := d.ListSecretFiles(prefix)
	if err != nil {
		if d.Config.Debug {
			log.Printf("Error listing files: %v\n", err)
		}
		return secrets
	}

	for _, file := range files {
		if !strings.HasSuffix(file, d.Config.EnvSuffix) {
			continue
		}
		if filepath.Join(d.Config.DataDir, file) == d.Config.IndexFile {
			continue
		}
		value, err := d.Filehandler.ReadFile(filepath.Join(d.Config.DataDir, file))
		if err != nil {
			if d.Config.Debug {
				log.Printf("Error reading file %s: %v\n", file, err)
			}
			continue
		}
		dynamicEnvValue, err := d.LoadValue(value)
		if err != nil {
			if d.Config.Debug {
				log.Printf("Error parsing file %s: %v\n", file, err)
			}
			continue
		}
		uid := strings.TrimSuffix(file, d.Config.EnvSuffix)
		secrets[uid] = dynamicEnvValue
	}
	return secrets
}

func (d *SecretManager) LoadIndex() *map[string]string {
	if d.index != nil {
		return d.index
	}
	index := make(map[string]string)
	d.index = &index
	data, err := d.Filehandler.ReadFile(d.Config.IndexFile)
	if err != nil {
		return d.index
	}
	decrypted, err := d.DecryptData(data)
	if err != nil {
		if d.Config.Debug {
			log.Printf("Error decrypting index: %v\n", err)
		}
		return d.index
	}
	if err := yaml.Unmarshal([]byte(decrypted), &index); err != nil {
		return d.index
	}
	return d.index
}

func (d *SecretManager) SaveIndex(index *map[string]string) error {
	indexContent, err := yaml.Marshal(index)
	if err != nil {
		return err
	}
	d.index = index
	encrypted, err := d.EncryptData(string(indexContent))
	if err != nil {
		return err
	}
	return d.Filehandler.WriteFile(d.Config.IndexFile, encrypted)
}

func (d *SecretManager) BuildIndex() error {
	secrets := d.ListItems("")
	index := make(map[string]string)
	idCounts := make(map[string]int)

	for uid, value := range secrets {
		baseID := value.Data["__id"].(string)
		idCounts[baseID]++
		if idCounts[baseID] > 1 {
			index[uid] = fmt.Sprintf("%s (%d)", baseID, idCounts[baseID]-1)
		} else {
			index[uid] = baseID
		}
	}
	return d.SaveIndex(&index)
}

func (d *SecretManager) UpdateIndex(uid string, id string, idFrom string) error {
	index := d.LoadIndex()
	if id == "" {
		delete(*index, uid)
	} else {
		(*index)[uid] = id
	}
	return d.SaveIndex(d.index)
}

func (d *SecretManager) GetSecretUID(key string) (string, error) {
	index := d.LoadIndex()
	for iUid, iId := range *index {
		if iId == key {
			return iUid, nil
		}
	}
	return "", fmt.Errorf("secret %q not found", key)
}

func (d *SecretManager) GetOrCreateSecretUID(key string) (string, error) {
	uid, err := d.GetSecretUID(key)
	if err == nil {
		return uid, nil
	}

	nid, err := gonanoid.New()
	if err != nil {
		return "", errors.New("failed to generate ID: " + err.Error())
	}
	return nid, nil
}

func (d *SecretManager) GetSecretPath(uid string) string {
	path := filepath.Join(d.Config.DataDir, uid+d.Config.EnvSuffix)
	return path
}

func (d *SecretManager) GetSecret(key string) (*Secret, error) {
	uid, err := d.GetSecretUID(key)
	if err != nil {
		return nil, err
	}
	path := d.GetSecretPath(uid)
	data, err := d.Filehandler.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dynamicEnvValue, err := d.LoadValue(data)
	return dynamicEnvValue, err
}

func (d *SecretManager) SetSecret(oldID string, value *Secret) error {
	if value == nil {
		return errors.New("value is nil")
	}

	newID := value.Data["__id"].(string)

	if oldID != newID {
		// Renaming: check if target key already exists
		index := d.LoadIndex()
		for _, id := range *index {
			if id == newID {
				return fmt.Errorf("secret %q already exists", newID)
			}
		}
	}

	uid, err := d.GetOrCreateSecretUID(oldID)
	if err != nil {
		return err
	}

	data, err := d.FormatValue(value)
	if err != nil {
		return err
	}

	encrypted, err := d.EncryptData(data)
	if err != nil {
		return err
	}

	path := d.GetSecretPath(uid)
	if err := d.Filehandler.WriteFile(path, encrypted); err != nil {
		return err
	}

	return d.UpdateIndex(uid, newID, oldID)
}

func (d *SecretManager) DeleteSecret(key string) error {
	uid, err := d.GetSecretUID(key)
	if err != nil {
		return err
	}
	path := d.GetSecretPath(uid)
	err = d.Filehandler.DeleteFile(path)
	if err != nil {
		return err
	}
	return d.UpdateIndex(uid, "", key)
}

func (d *SecretManager) ListSecrets() ([]string, error) {
	index := d.LoadIndex()
	keys := make([]string, 0, len(*index))
	for _, iId := range *index {
		keys = append(keys, iId)
	}
	return keys, nil
}

func (d *SecretManager) ParseSecret(key string) (*Vars, error) {
	parsed, err := d.GetSecret(key)
	if err != nil {
		return nil, errors.New("data not found: " + key)
	}

	result := Vars{Local: make(map[string]string), Env: make(map[string]string)}

	for k, v := range parsed.Data {
		strVal := fmt.Sprintf("%v", v)
		if strings.HasPrefix(k, "__") {
			continue
		}
		if strings.HasPrefix(k, "_") {
			result.Local[k] = strVal
		} else {
			result.Env[k] = strVal
		}
	}

	for k, v := range result.Env {
		result.Env[k] = resolveVariables(v, result.Local)
	}

	return &result, nil
}

func resolveVariables(value string, local map[string]string) string {
	return os.Expand(value, func(variable string) string {
		if variable == "$" {
			return "$"
		}
		if val, ok := local[variable]; ok {
			return val
		}
		return ""
	})
}

func (d *SecretManager) GetSecrets(keys []string) map[string]string {
	secrets := make(map[string]string)
	for _, key := range keys {
		parsed, err := d.ParseSecret(key)
		if err != nil {
			if d.Config.Debug {
				log.Printf("Error parsing secret %s: %v\n", key, err)
			}
			continue
		}
		for k, v := range parsed.Env {
			secrets[k] = v
		}
	}
	return secrets
}

func (d *SecretManager) VerifyIdentities() error {
	cmd := exec.Command("age-keygen", "-y", d.Config.Identities)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to verify identities: %w", err)
	}

	identities := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, identity := range identities {
		for _, recipient := range d.UserConfig.Data.Recipients {
			if identity == recipient {
				return nil
			}
		}
	}

	return errors.New("no matching identity found in recipients")
}

func (d *SecretManager) ReencryptAll() error {
	err := d.VerifyIdentities()
	if err != nil {
		return err
	}

	secrets := d.ListItems("")
	for _, value := range secrets {
		d.SetSecret(value.Data["__id"].(string), value)
	}
	return nil
}

func (d *SecretManager) ExportTree(outDir string, prefix string) ([]string, error) {
	fs := filehandler.NewFileHandler(outDir, d.Config.Debug)
	secrets := d.ListItems(prefix)
	fmt.Println("Loaded", len(secrets), "files")
	keys := make([]string, 0, len(secrets))
	for _, value := range secrets {
		key := value.Data["__id"].(string)
		keys = append(keys, key)
		path, err := filepath.Rel(prefix, key)
		path = strings.ReplaceAll(path, "\\", "/")
		if err != nil || strings.HasPrefix(path, "..") {
			return nil, fmt.Errorf("failed to get relative path: %w", err)
		}

		output, err := d.FormatValue(value)
		if err != nil {
			return nil, fmt.Errorf("failed to format value: %w", err)
		}

		err = fs.WriteFile(path, output)
		if err != nil {
			return nil, fmt.Errorf("failed to write file: %w", err)
		}
	}
	return keys, nil
}

func (d *SecretManager) ImportTree(inDir string, prefix string, conflict string) ([]string, error) {
	fs := filehandler.NewFileHandler(inDir, d.Config.Debug)
	files, err := fs.ListFiles("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}
	fmt.Println("Loaded", len(files), "files")
	keys := make([]string, 0, len(files))
	for _, file := range files {
		value, err := fs.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}

		secret, err := d.ParseRawValue(value)
		if err != nil {
			secret = &Secret{
				Data: map[string]any{"__id": file},
			}
			if err := yaml.Unmarshal([]byte(value), &secret.Data); err != nil {
				return nil, fmt.Errorf("failed to parse file: %w", err)
			}
		}

		id := secret.Data["__id"].(string)
		sanitizedID := d.SanitizeID(id)

		existing, err := d.GetSecret(sanitizedID)
		if err == nil {
			existingFormatted, _ := d.FormatValue(existing)
			newFormatted, _ := d.FormatValue(secret)
			if existingFormatted == newFormatted {
				fmt.Printf("Warning: %q has identical data, skipping\n", sanitizedID)
				continue
			}

			switch conflict {
			case "abort":
				return nil, fmt.Errorf("secret %q already exists, use --conflict skip or overwrite", sanitizedID)
			case "skip":
				fmt.Printf("Skipping %q (already exists)\n", sanitizedID)
				continue
			case "overwrite":
			default:
				return nil, fmt.Errorf("invalid --conflict value: %q (must be abort, skip, or overwrite)", conflict)
			}
		}

		err = d.SetSecret(sanitizedID, secret)
		if err != nil {
			return nil, fmt.Errorf("failed to set secret: %w", err)
		}
		keys = append(keys, sanitizedID)
	}
	return keys, nil
}
