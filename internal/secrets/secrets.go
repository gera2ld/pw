package secrets

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"pw/internal/config"
	"pw/internal/filehandler"

	gonanoid "github.com/matoous/go-nanoid/v2"
	"gopkg.in/yaml.v3"
)

// maxFilenameLen caps the sanitized base name of a secret file (before the
// uniqueness suffix and the .age extension) so on-disk paths stay portable.
const maxFilenameLen = 40

// nanoidAlphabet / nanoidLen control the generated filenames used in obscure
// mode. Lowercase, digits, underscore and hyphen so on-disk names are friendly.
const (
	nanoidAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz_-"
	nanoidLen      = 12
)

// newNanoid returns a fresh lowercase random id used as an obscure-mode filename.
func newNanoid() (string, error) {
	return gonanoid.Generate(nanoidAlphabet, nanoidLen)
}

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

func sanitizeIDString(id string) string {
	re := regexp.MustCompile(`[^\w+\-/@.]`)
	return re.ReplaceAllString(id, "-")
}

func (d *SecretManager) SanitizeID(id string) string {
	return sanitizeIDString(id)
}

// nonAlnumRe matches runs of characters that are not part of a lowercase
// filename (letters, digits, underscore, hyphen), collapsing them to a hyphen.
var nonAlnumRe = regexp.MustCompile(`[^a-z0-9_-]+`)

var validNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func isValidNamePart(s string) bool {
	if len(s) == 0 || len(s) > maxFilenameLen {
		return false
	}
	return validNameRe.MatchString(s)
}

func IsValidKey(key string) bool {
	if key == "" {
		return false
	}
	for _, p := range strings.Split(key, "/") {
		if !isValidNamePart(p) {
			return false
		}
	}
	return true
}

func isValidKey(key string) bool { return IsValidKey(key) }

// normalizeFilename sanitizes a secret name into a lowercase kebab-case file
// base name: it lowercases, collapses non-alphanumeric runs to single hyphens,
// trims edge hyphens, and caps the length so the resulting path stays portable.
func normalizeFilename(name string) string {
	s := strings.ToLower(name)
	s = nonAlnumRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "secret"
	}
	if len(s) > maxFilenameLen {
		s = s[:maxFilenameLen]
		s = strings.Trim(s, "-")
		if s == "" {
			s = "secret"
		}
	}
	return s
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

	name, _ := data["__name"].(string)
	if name == "" {
		// Fall back to __id when reindexing legacy files: use it as __name.
		if id, _ := data["__id"].(string); id != "" {
			name = id
			data["__name"] = name
		}
	}
	if name == "" {
		return nil, errors.New("invalid: missing or invalid '__name'")
	}
	if !isValidKey(name) {
		return nil, fmt.Errorf("invalid '__name' %q: each part must be a valid name", name)
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

func (d *SecretManager) ValidateTemplates(secret *Secret) error {
	for k, v := range secret.Data {
		strVal := fmt.Sprintf("%v", v)
		if _, err := template.New("").Option("missingkey=zero").Parse(strVal); err != nil {
			return fmt.Errorf("invalid template in field %q: %w", k, err)
		}
	}
	return nil
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

// storedFileData returns a copy of the secret's data as it should be written to
// disk: only the secret's name is stored (not the full id path).
func storedFileData(data map[string]any, fullID string) map[string]any {
	fileData := make(map[string]any, len(data))
	for k, v := range data {
		fileData[k] = v
	}
	delete(fileData, "__id")
	fileData["__name"] = filepath.Base(fullID)
	return fileData
}

func (d *SecretManager) EncryptData(data string, recipients []string) (string, error) {
	if len(recipients) == 0 {
		return "", errors.New("no recipient is added")
	}

	args := []string{"-a"}
	for _, recipient := range recipients {
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
		return nil, err
	}
	return d.ParseRawValue(value)
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
	encrypted, err := d.EncryptData(string(indexContent), d.UserConfig.GetRecipientsForPath("."))
	if err != nil {
		return err
	}
	return d.Filehandler.WriteFile(d.Config.IndexFile, encrypted)
}
func (d *SecretManager) BuildIndex() error {
	secrets := d.ListItems("")

	index := make(map[string]string)
	used := make(map[string]bool)

	uids := make([]string, 0, len(secrets))
	for uid := range secrets {
		uids = append(uids, uid)
	}
	sort.Strings(uids)

	for _, uid := range uids {
		value := secrets[uid]
		rawName := rawNameOf(value.Data)
		_, hasLegacyID := value.Data["__id"]
		hasSlash := strings.Contains(rawName, "/")
		fullID := d.fullIDFromUID(uid, rawName)
		name := rawName
		dir := filepath.Dir(fullID)

		var targetUID string
		obscure := d.UserConfig.GetObscureNamesForPath(dir)
		if obscure {
			// Keep nanoid-style filenames as-is; migrate readable ones to a nanoid.
			if !isReadableFilename(uid, name) {
				targetUID = uid
			} else {
			nid, err := newNanoid()
			if err != nil {
				return errors.New("failed to generate ID: " + err.Error())
			}
			targetUID = filepath.Join(dir, nid)
			}
		} else {
			// Reuse an existing readable filename; otherwise assign a unique one.
			if isReadableFilename(uid, name) && !used[uid] {
				targetUID = uid
			} else {
				base := normalizeFilename(filepath.Base(name))
				targetUID = filepath.Join(dir, base)
				for i := 2; used[targetUID]; i++ {
					targetUID = filepath.Join(dir, fmt.Sprintf("%s.%d", base, i))
				}
			}
		}

		used[targetUID] = true

		needsRewrite := hasLegacyID || hasSlash
		if targetUID != uid {
			if err := d.Filehandler.MoveFile(d.GetSecretPath(uid), d.GetSecretPath(targetUID)); err != nil {
				if d.Config.Debug {
					log.Printf("Error migrating %s: %v\n", uid, err)
				}
				targetUID = uid
			} else {
				needsRewrite = true
			}
		}

		if needsRewrite {
			// Rewrite content to ensure __name is relative and __id is removed.
			data, err := d.FormatValue(&Secret{Data: storedFileData(value.Data, fullID), Payload: value.Payload})
			if err == nil {
				recipients := d.UserConfig.GetRecipientsForPath(filepath.Dir(fullID))
				if enc, e := d.EncryptData(data, recipients); e == nil {
					_ = d.Filehandler.WriteFile(d.GetSecretPath(targetUID), enc)
				}
			}
		}

		index[targetUID] = fullID
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

	if d.UserConfig.GetObscureNamesForPath(filepath.Dir(key)) {
		nid, err := newNanoid()
		if err != nil {
			return "", errors.New("failed to generate ID: " + err.Error())
		}
		return filepath.Join(filepath.Dir(key), nid), nil
	}

	index := d.LoadIndex()
	return d.uniqueReadableUID(key, index, ""), nil
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
	if err != nil {
		return nil, err
	}
	return dynamicEnvValue, err
}

// fullIDFromUID reconstructs the full id from a file's location (uid, relative
// to the data dir) and the name stored inside it.
func (d *SecretManager) fullIDFromUID(uid string, name string) string {
	return filepath.Join(filepath.Dir(uid), name)
}

// rawNameOf returns the stored name of a secret from its __name field.
func rawNameOf(data map[string]any) string {
	if n, ok := data["__name"].(string); ok {
		return n
	}
	return ""
}

// isReadableFilename reports whether a secret's on-disk uid is already a
// readable (name-based) filename for the given secret name, i.e. either the
// normalized name or the normalized name with a ".N" uniqueness suffix.
// name is the relative __name and may contain "/" for sub-paths.
func isReadableFilename(uid string, name string) bool {
	norm := normalizeFilename(filepath.Base(name))
	base := filepath.Base(uid)
	if base == norm {
		return true
	}
	if strings.HasPrefix(base, norm+".") {
		suffix := strings.TrimPrefix(base, norm+".")
		if n, err := strconv.Atoi(suffix); err == nil && n >= 2 {
			return true
		}
	}
	return false
}

// uniqueReadableUID returns a unique uid for a secret in readable mode, derived
// from its name. It prefers a name with a ".N" suffix to avoid colliding with
// uids already present in the index, excluding excludeUID (the file being
// moved).
func (d *SecretManager) uniqueReadableUID(fullID string, index *map[string]string, excludeUID string) string {
	dir := filepath.Dir(fullID)
	base := normalizeFilename(filepath.Base(fullID))
	candidate := filepath.Join(dir, base)
	for i := 2; ; i++ {
		if candidate != excludeUID {
			if _, exists := (*index)[candidate]; !exists {
				break
			}
		}
		candidate = filepath.Join(dir, fmt.Sprintf("%s.%d", base, i))
	}
	return candidate
}

func (d *SecretManager) SetSecret(oldID string, value *Secret) error {
	if value == nil {
		return errors.New("value is nil")
	}

	rawName, _ := value.Data["__name"].(string)
	if rawName == "" {
		return errors.New("invalid: missing or invalid '__name'")
	}
	if !isValidKey(rawName) {
		return fmt.Errorf("invalid '__name' %q: each part must be a valid name", rawName)
	}
	if !isValidKey(oldID) {
		return fmt.Errorf("invalid id %q: each part must be a valid name", oldID)
	}
	// __name is always the relative name (may contain "/" for sub-paths);
	// it is mirrored to directories relative to the old id's directory.
	fullID := filepath.Clean(filepath.Join(filepath.Dir(oldID), rawName))
	if !isValidKey(fullID) {
		return fmt.Errorf("invalid id %q: each part must be a valid name", fullID)
	}

	if oldID != fullID {
		// Renaming: check if target key already exists
		index := d.LoadIndex()
		for _, id := range *index {
			if id == fullID {
				return fmt.Errorf("secret %q already exists", fullID)
			}
		}
	}

	uid, err := d.GetOrCreateSecretUID(oldID)
	if err != nil {
		return err
	}

	// Place the file under dirname(fullID), keeping the nanoid in obscure mode
	// or using a unique name-based filename otherwise.
	var targetUID string
	if d.UserConfig.GetObscureNamesForPath(filepath.Dir(fullID)) {
		targetUID = filepath.Join(filepath.Dir(fullID), filepath.Base(uid))
	} else if oldID == fullID {
		// Updating an existing secret: keep its current uid.
		targetUID = uid
	} else {
		// Renaming (or a new secret whose name collides): derive a unique uid,
		// excluding the file currently being replaced.
		index := d.LoadIndex()
		targetUID = d.uniqueReadableUID(fullID, index, uid)
	}

	// Store only the name inside the file, not the full path.
	data, err := d.FormatValue(&Secret{Data: storedFileData(value.Data, fullID), Payload: value.Payload})
	if err != nil {
		return err
	}

	recipients := d.UserConfig.GetRecipientsForPath(filepath.Dir(fullID))
	encrypted, err := d.EncryptData(data, recipients)
	if err != nil {
		return err
	}

	if err := d.Filehandler.WriteFile(d.GetSecretPath(targetUID), encrypted); err != nil {
		return err
	}

	if targetUID != uid {
		if err := d.Filehandler.DeleteFile(d.GetSecretPath(uid)); err != nil {
			return err
		}
	}

	index := d.LoadIndex()
	delete(*index, uid)
	(*index)[targetUID] = fullID
	return d.SaveIndex(d.index)
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
	tmpl := template.New("").
		Option("missingkey=zero")
	tmpl, err := tmpl.Parse(value)
	if err != nil {
		return value
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, local); err != nil {
		return value
	}
	return sb.String()
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
	recipients := d.UserConfig.GetRecipientsForPath(".")

	for _, identity := range identities {
		for _, recipient := range recipients {
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
	for uid, value := range secrets {
		fullID := d.fullIDFromUID(uid, rawNameOf(value.Data))
		d.SetSecret(fullID, value)
	}
	return nil
}

func (d *SecretManager) ExportTree(outDir string, prefix string) ([]string, error) {
	fs := filehandler.NewFileHandler(outDir, d.Config.Debug)
	secrets := d.ListItems(prefix)
	fmt.Println("Loaded", len(secrets), "files")
	keys := make([]string, 0, len(secrets))
	for uid, value := range secrets {
		fullID := d.fullIDFromUID(uid, value.Data["__name"].(string))
		keys = append(keys, fullID)
		path, err := filepath.Rel(prefix, fullID)
		path = strings.ReplaceAll(path, "\\", "/")
		if err != nil || strings.HasPrefix(path, "..") {
			return nil, fmt.Errorf("failed to get relative path: %w", err)
		}

		// Export stores only the name; the path is implied by the file location.
		output, err := d.FormatValue(&Secret{Data: storedFileData(value.Data, fullID), Payload: value.Payload})
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
	skipped := make([]string, 0)
	for _, file := range files {
		value, err := fs.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}

		secret, err := d.ParseRawValue(value)
		if err != nil {
			secret = &Secret{
				Data: map[string]any{"__name": filepath.Base(file)},
			}
			if err := yaml.Unmarshal([]byte(value), &secret.Data); err != nil {
				return nil, fmt.Errorf("failed to parse file: %w", err)
			}
			// Ensure __name stays relative (basename).
			if n, ok := secret.Data["__name"].(string); ok {
				secret.Data["__name"] = filepath.Base(n)
			}
		}

		if err := d.ValidateTemplates(secret); err != nil {
			fmt.Printf("Skipping %q (invalid template: %v)\n", file, err)
			skipped = append(skipped, file)
			continue
		}

		id := strings.ReplaceAll(file, "\\", "/")
		id = strings.TrimSuffix(id, d.Config.EnvSuffix)
		sanitizedID := d.SanitizeID(id)
		// __name is the relative name (basename); the full id is sanitizedID.
		secret.Data["__name"] = filepath.Base(sanitizedID)

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
	if len(skipped) > 0 {
		fmt.Printf("Skipped %d file(s) due to invalid templates: %v\n", len(skipped), skipped)
	}
	return keys, nil
}
