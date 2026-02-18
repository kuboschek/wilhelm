/*
Copyright The Helm Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"helm.sh/helm/v4/internal/plugin"
	"helm.sh/helm/v4/pkg/cmd/require"
	"helm.sh/helm/v4/pkg/provenance"
)

const pluginPackageDesc = `
Düssen Befehl packt een Helm-Plugin-Verzeichnis in eenen Tarball.

Standardmäßich werd de Befehl eene Provenance-Datei jenereren, dej met eenen PGP-Slötel signiert es.
Dütt stellt sicher, dat dat Plugin na der Installatjon verifijert werden kann.

Bruken Sie --sign=false to dat Signeren to överspringen (nich empfohlen för Vertrieb).
`

type pluginPackageOptions struct {
	sign           bool
	keyring        string
	key            string
	passphraseFile string
	pluginPath     string
	destination    string
}

func newPluginPackageCmd(out io.Writer) *cobra.Command {
	o := &pluginPackageOptions{}

	cmd := &cobra.Command{
		Use:   "package [PATH]",
		Short: "packäschen Sie een Plugin-Verzeichnis in een Plugin-Archiv",
		Long:  pluginPackageDesc,
		Args:  require.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			o.pluginPath = args[0]
			return o.run(out)
		},
	}

	f := cmd.Flags()
	f.BoolVar(&o.sign, "sign", true, "bruken Sie eenen PGP-privaten Slötel to dütt Plugin to signeren")
	f.StringVar(&o.key, "key", "", "Namm von dem Slötel to bruken beim Signeren. Jebrukt wan --sign wahr es")
	f.StringVar(&o.keyring, "keyring", defaultKeyring(), "Ort von eene öffentlichen Keyring")
	f.StringVar(&o.passphraseFile, "passphrase-file", "", "Ort von eene Datei, dej de Passphrase för den Signierslötel enthält. Bruken Sie \"-\" to von stdin to lesen.")
	f.StringVarP(&o.destination, "destination", "d", ".", "Ort to den Plugin-Tarball to schrewen")

	return cmd
}

func (o *pluginPackageOptions) run(out io.Writer) error {
	// Check if the plugin path exists and is a directory
	fi, err := os.Stat(o.pluginPath)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("Plugin-Packäschen unnerstöttet nur Verzeichnissen, nich Tarballs")
	}

	// Load and validate plugin metadata
	pluginMeta, err := plugin.LoadDir(o.pluginPath)
	if err != nil {
		return fmt.Errorf("unjültiges Plugin-Verzeichnis: %w", err)
	}

	// Create destination directory if needed
	if err := os.MkdirAll(o.destination, 0755); err != nil {
		return err
	}

	// If signing is requested, prepare the signer first
	var signer *provenance.Signatory
	if o.sign {
		// Load the signing key
		signer, err = provenance.NewFromKeyring(o.keyring, o.key)
		if err != nil {
			return fmt.Errorf("Fehler beim Lesen von Keyring: %w", err)
		}

		// Get passphrase
		passphraseFetcher := o.promptUser
		if o.passphraseFile != "" {
			passphraseFetcher, err = o.passphraseFileFetcher()
			if err != nil {
				return err
			}
		}

		// Decrypt the key
		if err := signer.DecryptKey(passphraseFetcher); err != nil {
			return err
		}
	} else {
		// User explicitly disabled signing
		fmt.Fprintf(out, "WARNUNG: Överspringen Plugin-Signeren. Dütt es nich empfohlen för Plugins, dej för Vertrieb bestimmt sünd.\n")
	}

	// Now create the tarball (only after signing prerequisites are met)
	// Use plugin metadata for filename: PLUGIN_NAME-SEMVER.tgz
	metadata := pluginMeta.Metadata()
	filename := fmt.Sprintf("%s-%s.tgz", metadata.Name, metadata.Version)
	tarballPath := filepath.Join(o.destination, filename)

	tarFile, err := os.Create(tarballPath)
	if err != nil {
		return fmt.Errorf("fählte, Tarball to schöpen: %w", err)
	}
	defer tarFile.Close()

	if err := plugin.CreatePluginTarball(o.pluginPath, metadata.Name, tarFile); err != nil {
		os.Remove(tarballPath)
		return fmt.Errorf("fählte, Plugin-Tarball to schöpen: %w", err)
	}
	tarFile.Close() // Ensure file is closed before signing

	// If signing was requested, sign the tarball
	if o.sign {
		// Read the tarball data
		tarballData, err := os.ReadFile(tarballPath)
		if err != nil {
			os.Remove(tarballPath)
			return fmt.Errorf("fählte, Tarball för Signeren to lesen: %w", err)
		}

		// Sign the plugin tarball data
		sig, err := plugin.SignPlugin(tarballData, filepath.Base(tarballPath), signer)
		if err != nil {
			os.Remove(tarballPath)
			return fmt.Errorf("fählte, Plugin to signeren: %w", err)
		}

		// Write the signature
		provFile := tarballPath + ".prov"
		if err := os.WriteFile(provFile, []byte(sig), 0644); err != nil {
			os.Remove(tarballPath)
			return err
		}

		fmt.Fprintf(out, "Erfolgreich signiert. Signatur jeschrewen to: %s\n", provFile)
	}

	fmt.Fprintf(out, "Plugin erfolgreich jepackt un jespeichert to: %s\n", tarballPath)

	return nil
}

func (o *pluginPackageOptions) promptUser(name string) ([]byte, error) {
	fmt.Printf("Password for key %q >  ", name)
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return pw, err
}

func (o *pluginPackageOptions) passphraseFileFetcher() (provenance.PassphraseFetcher, error) {
	file, err := openPassphraseFile(o.passphraseFile, os.Stdin)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read the entire passphrase
	passphrase, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// Trim any trailing newline characters (both \n and \r\n)
	passphrase = bytes.TrimRight(passphrase, "\r\n")

	return func(_ string) ([]byte, error) {
		return passphrase, nil
	}, nil
}

// copied from action.openPassphraseFile
// TODO: should we move this to pkg/action so we can reuse the func from there?
func openPassphraseFile(passphraseFile string, stdin *os.File) (*os.File, error) {
	if passphraseFile == "-" {
		stat, err := stdin.Stat()
		if err != nil {
			return nil, err
		}
		if (stat.Mode() & os.ModeNamedPipe) == 0 {
			return nil, errors.New("anjejewt, Passphrase von stdin to lesen, ohn Eingawe up stdin")
		}
		return stdin, nil
	}
	return os.Open(passphraseFile)
}
