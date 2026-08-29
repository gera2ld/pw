package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"pw/internal/secrets"
	"pw/internal/update"
	"slices"

	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func NewRootCommand(version string, builtAt string, sm *secrets.SecretManager) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "pw",
		Short:   "Minimalist CLI Secret Manager",
		Version: version,
	}
	cmd.SetVersionTemplate("pw {{.Version}}\nbuilt at " + builtAt + "\n")

	cmd.AddCommand(newRunCommand(sm))
	cmd.AddCommand(newRmCommand(sm))
	cmd.AddCommand(newImportCommand(sm))
	cmd.AddCommand(newExportCommand(sm))
	cmd.AddCommand(newLsCommand(sm))
	cmd.AddCommand(newMvCommand(sm))
	cmd.AddCommand(newEditCommand(sm))
	cmd.AddCommand(newRcpCommand(sm))
	cmd.AddCommand(newReindexCommand(sm))
	cmd.AddCommand(newShowCommand(sm))
	cmd.AddCommand(newEnvCommand(sm))
	if update.Repo != "" {
		cmd.AddCommand(newUpdateCommand(version))
	}

	return cmd
}

func newRunCommand(sm *secrets.SecretManager) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run <id>... -- <command>",
		Short: "Run command with secrets injected",
		Long: `Run a command with secrets loaded from the specified IDs.
Use -- to separate IDs from the command.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			dashIndex := cmd.ArgsLenAtDash()

			if dashIndex == -1 {
				return errors.New("missing '--' separator between IDs and command")
			}

			ids := args[:dashIndex]
			for _, id := range ids {
				if !secrets.IsValidKey(id) {
					return fmt.Errorf("invalid id %q: each part must be a valid name", id)
				}
			}
			targetCmd := args[dashIndex:]

			envVars := sm.GetSecrets(ids)

			env := os.Environ()
			for key, value := range envVars {
				env = append(env, fmt.Sprintf("%s=%s", key, value))
			}

			cmdExec := exec.Command(targetCmd[0], targetCmd[1:]...)
			cmdExec.Env = env
			cmdExec.Stdout = os.Stdout
			cmdExec.Stderr = os.Stderr
			cmdExec.Stdin = os.Stdin

			err := cmdExec.Run()
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					os.Exit(exitErr.ExitCode())
				}
				return fmt.Errorf("failed to run command: %w", err)
			}
			return nil
		},
	}

	return cmd
}

func newRmCommand(sm *secrets.SecretManager) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <id>",
		Short: "Delete the physical file and update index",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			if !secrets.IsValidKey(id) {
				return fmt.Errorf("invalid id %q: each part must be a valid name", id)
			}
			err := sm.DeleteSecret(id)
			return err
		},
	}
}

func newImportCommand(sm *secrets.SecretManager) *cobra.Command {
	var conflict string

	cmd := &cobra.Command{
		Use:   "import <source>",
		Short: "Import data from a directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			source := args[0]

			ids, err := sm.ImportTree(source, "", conflict)
			if err != nil {
				return fmt.Errorf("failed to import data from %s: %w", source, err)
			}

			fmt.Printf("Successfully imported %d ids from %s\n", len(ids), source)
			return nil
		},
	}

	cmd.Flags().StringVar(&conflict, "conflict", "abort", "Conflict resolution: abort, skip, or overwrite")

	return cmd
}

func newExportCommand(sm *secrets.SecretManager) *cobra.Command {
	var outDir string
	var prefix string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export all data to a directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outDir == "" {
				outDir = "vault-export"
			}

			ids, err := sm.ExportTree(outDir, prefix)
			if err != nil {
				return fmt.Errorf("failed to export data: %w", err)
			}

			fmt.Printf("Exported %d ids to %s\n", len(ids), outDir)
			return nil
		},
	}

	cmd.Flags().StringVarP(&outDir, "outDir", "o", "vault-export", "Output directory")
	cmd.Flags().StringVar(&prefix, "prefix", "", "Filter the ids by the prefix and strip it when writing to files")

	return cmd
}

func newLsCommand(sm *secrets.SecretManager) *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all indexed secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := sm.ListSecrets()
			if err != nil {
				return err
			}
			slices.Sort(ids)
			for _, id := range ids {
				fmt.Println(id)
			}
			return nil
		},
	}
}

func newMvCommand(sm *secrets.SecretManager) *cobra.Command {
	return &cobra.Command{
		Use:   "mv <id> <new_id>",
		Short: "Rename a secret and refresh index",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			newID := args[1]
			if !secrets.IsValidKey(id) {
				return fmt.Errorf("invalid id %q: each part must be a valid name", id)
			}
			if !secrets.IsValidKey(newID) {
				return fmt.Errorf("invalid id %q: each part must be a valid name", newID)
			}
			parsed, err := sm.GetSecret(id)
			if err != nil {
				return err
			}
			// __name is relative; store a path relative to the old id's directory
			// so SetSecret can mirror it correctly.
			rel, err := filepath.Rel(filepath.Dir(id), newID)
			if err != nil {
				rel = filepath.Base(newID)
			}
			parsed.Data["__name"] = rel
			return sm.SetSecret(id, parsed)
		},
	}
}

func newEditCommand(sm *secrets.SecretManager) *cobra.Command {
	return &cobra.Command{
		Use:   "edit <id>",
		Short: "Edit the value of a secret with $EDITOR",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			if !secrets.IsValidKey(id) {
				return fmt.Errorf("invalid id %q: each part must be a valid name", id)
			}

			editor := os.Getenv("EDITOR")
			if editor == "" {
				return errors.New("$EDITOR is not set")
			}

			parsed, err := sm.GetSecret(id)
			var oldValue string
			if err != nil {
				fmt.Println("Editing new secret")
				oldValue = fmt.Sprintf("__name: %s\n", filepath.Base(id))
			} else {
				if parsed.Data == nil {
					parsed.Data = make(map[string]any)
				}
				value, err := sm.FormatValue(parsed)
				if err != nil {
					return fmt.Errorf("failed to format value: %w", err)
				}
				oldValue = value
			}

			nid, err := gonanoid.New()
			if err != nil {
				return fmt.Errorf("failed to generate temp ID: %w", err)
			}
			tempFile, err := os.CreateTemp("", fmt.Sprintf("pw-edit-%s-*.yml", nid))
			if err != nil {
				return fmt.Errorf("failed to create temporary file: %w", err)
			}
			defer os.Remove(tempFile.Name())

			if _, err := tempFile.WriteString(oldValue); err != nil {
				return fmt.Errorf("failed to write to temporary file: %w", err)
			}
			tempFile.Close()

			cmdExec := exec.Command(editor, tempFile.Name())
			cmdExec.Stdout = os.Stdout
			cmdExec.Stderr = os.Stderr
			cmdExec.Stdin = os.Stdin

			if err := cmdExec.Run(); err != nil {
				return fmt.Errorf("failed to open editor: %w", err)
			}

			newValueBytes, err := os.ReadFile(tempFile.Name())
			if err != nil {
				return fmt.Errorf("failed to read temporary file: %w", err)
			}
			newValue := string(newValueBytes)

			if newValue == "" {
				fmt.Println("No changes made.")
				return nil
			}

			parsed, err = sm.ParseRawValue(newValue)
			if err != nil {
				return fmt.Errorf("failed to parse new value: %w\nMake sure to include __name: %s", err, id)
			}

			if err := sm.ValidateTemplates(parsed); err != nil {
				return fmt.Errorf("failed to validate templates: %w", err)
			}

			rawName := parsed.Data["__name"].(string)
			// __name is always relative (may contain "/" for sub-paths);
			// it is mirrored to directories relative to dirname(id).
			newID := filepath.Join(filepath.Dir(id), rawName)
			if newID == "." {
				newID = rawName
			}
			newID = filepath.Clean(newID)

			if newValue == oldValue && newID == id {
				fmt.Println("No changes made.")
				return nil
			}

			if err := sm.SetSecret(id, parsed); err != nil {
				return fmt.Errorf("failed to save updated value: %w", err)
			}

			if newID != id {
				fmt.Printf("Renamed %s to %s\n", id, newID)
			} else {
				fmt.Println("Updated id:", id)
			}
			return nil
		},
	}
}

func newRcpCommand(sm *secrets.SecretManager) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rcp",
		Short: "Manage age recipients (public keys)",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "ls",
		Short: "List all recipients",
		RunE: func(cmd *cobra.Command, args []string) error {
			recipients := sm.UserConfig.Data.Recipients
			for _, recipient := range recipients {
				fmt.Println(recipient)
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "add <recipient>",
		Short: "Add a recipient",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			recipient := args[0]
			return sm.UserConfig.AddRecipient(recipient)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "rm <recipient>",
		Short: "Remove a recipient",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			recipient := args[0]
			return sm.UserConfig.RemoveRecipient(recipient)
		},
	})

	return cmd
}

func newReindexCommand(sm *secrets.SecretManager) *cobra.Command {
	return &cobra.Command{
		Use:   "reindex",
		Short: "Rebuild index for all data",
		RunE: func(cmd *cobra.Command, args []string) error {
			return sm.BuildIndex()
		},
	}
}

func newShowCommand(sm *secrets.SecretManager) *cobra.Command {
	var showPayload, showRaw, showJSON bool

	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Decrypt and print secret content",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			if !secrets.IsValidKey(id) {
				return fmt.Errorf("invalid id %q: each part must be a valid name", id)
			}

			parsed, err := sm.GetSecret(id)
			if err != nil {
				return fmt.Errorf("failed to retrieve secret: %w", err)
			}

			if parsed.Data == nil {
				parsed.Data = make(map[string]any)
			}

			if showJSON {
				data, err := json.MarshalIndent(parsed.Data, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %w", err)
				}
				fmt.Println(string(data))
				return nil
			}

			if showPayload {
				fmt.Print(parsed.Payload)
				return nil
			}

			if showRaw {
				value, err := sm.FormatValue(parsed)
				if err != nil {
					return fmt.Errorf("failed to format value: %w", err)
				}
				fmt.Print(value)
				return nil
			}

			data, err := yaml.Marshal(parsed.Data)
			if err != nil {
				return fmt.Errorf("failed to marshal data: %w", err)
			}
			fmt.Print(string(data))
			return nil
		},
	}

	cmd.Flags().BoolVar(&showJSON, "json", false, "Show data as JSON")
	cmd.Flags().BoolVar(&showPayload, "payload", false, "Show payload only")
	cmd.Flags().BoolVar(&showRaw, "raw", false, "Show full raw content (data + payload)")

	return cmd
}

func newEnvCommand(sm *secrets.SecretManager) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env <id>...",
		Short: "Print merged environment variables to stdout",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, id := range args {
				if !secrets.IsValidKey(id) {
					return fmt.Errorf("invalid id %q: each part must be a valid name", id)
				}
			}
			merged := make(map[string]string)
			for _, id := range args {
				vars, err := sm.ParseSecret(id)
				if err != nil {
					return fmt.Errorf("failed to parse secret %q: %w", id, err)
				}
				for key, value := range vars.Env {
					merged[key] = value
				}
			}
			for key, value := range merged {
				fmt.Printf("%s=%s\n", key, value)
			}
			return nil
		},
	}

	return cmd
}

func newUpdateCommand(currentVersion string) *cobra.Command {
	var checkOnly bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check for and install updates",
		RunE: func(cmd *cobra.Command, args []string) error {
			latest, found, err := update.CheckLatest()
			if err != nil {
				return fmt.Errorf("failed to check for updates: %w", err)
			}
			if !found {
				fmt.Println("No update available for this platform")
				return nil
			}

			if latest != "" && latest == currentVersion {
				fmt.Println("Already up to date")
				return nil
			}

			fmt.Printf("Current: %s\n", currentVersion)
			if latest != "" {
				fmt.Printf("Latest: %s\n", latest)
			}
			if checkOnly {
				return nil
			}

			fmt.Print("Update to latest? (y/N) ")
			var confirm string
			fmt.Scanln(&confirm)
			if confirm != "y" && confirm != "Y" {
				fmt.Println("Aborted")
				return nil
			}

			if err := update.Install(); err != nil {
				return fmt.Errorf("failed to install update: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "Only check for updates, don't install")

	return cmd
}
