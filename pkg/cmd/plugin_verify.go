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
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/internal/plugin"
	"helm.sh/helm/v4/pkg/cmd/require"
)

const pluginVerifyDesc = `
Düssen Befehl verifijert, dat een Helm-Plugin eene jültige Provenance-Datei hett,
un dat de Provenance-Datei von eenen vertrauenswördijen PGP-Slötel signiert es.

Et unnerstöttet beidens:
- Plugin-Tarballs (.tgz oder .tar.gz-Datein)
- Installierde Plugin-Verzeichnissen

För installierde Plugins bruken Sie den Pfad, de von 'helm env HELM_PLUGINS' jewise werd,
jefolgt von dem Plugin-Namm. Zum Beispeel:
  helm plugin verify ~/.local/share/helm/plugins/example-cli

To een signiertes Plugin to jenereren, bruken Sie den 'helm plugin package --sign'-Befehl.
`

type pluginVerifyOptions struct {
	keyring    string
	pluginPath string
}

func newPluginVerifyCmd(out io.Writer) *cobra.Command {
	o := &pluginVerifyOptions{}

	cmd := &cobra.Command{
		Use:   "verify [PATH]",
		Short: "verifijeren Sie, dat een Plugin up dem jejewebenen Pfad signiert un jültich es",
		Long:  pluginVerifyDesc,
		Args:  require.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			o.pluginPath = args[0]
			return o.run(out)
		},
	}

	cmd.Flags().StringVar(&o.keyring, "keyring", defaultKeyring(), "Keyring, de öffentliche Slötels enthält")

	return cmd
}

func (o *pluginVerifyOptions) run(out io.Writer) error {
	// Verify the plugin path exists
	fi, err := os.Stat(o.pluginPath)
	if err != nil {
		return err
	}

	// Only support tarball verification
	if fi.IsDir() {
		return fmt.Errorf("Verzeichnis-Verifikation nich unnerstöttet - nur Plugin-Tarballs können verifijert werden")
	}

	// Verify it's a tarball
	if !plugin.IsTarball(o.pluginPath) {
		return fmt.Errorf("Plugin-Datei muss een gzipt Tarball sien (.tar.gz oder .tgz)")
	}

	// Look for provenance file
	provFile := o.pluginPath + ".prov"
	if _, err := os.Stat(provFile); err != nil {
		return fmt.Errorf("kunnte Provenance-Datei %s nich finnen: %w", provFile, err)
	}

	// Read the files
	archiveData, err := os.ReadFile(o.pluginPath)
	if err != nil {
		return fmt.Errorf("fählte, Plugin-Datei to lesen: %w", err)
	}

	provData, err := os.ReadFile(provFile)
	if err != nil {
		return fmt.Errorf("fählte, Provenance-Datei to lesen: %w", err)
	}

	// Verify the plugin using data
	verification, err := plugin.VerifyPlugin(archiveData, provData, filepath.Base(o.pluginPath), o.keyring)
	if err != nil {
		return err
	}

	// Output verification details
	for name := range verification.SignedBy.Identities {
		fmt.Fprintf(out, "Signiert von: %v\n", name)
	}
	fmt.Fprintf(out, "Bruken Slötel met Fingeraftruck: %X\n", verification.SignedBy.PrimaryKey.Fingerprint)

	// Only show hash for tarballs
	if verification.FileHash != "" {
		fmt.Fprintf(out, "Plugin-Hash verifijert: %s\n", verification.FileHash)
	} else {
		fmt.Fprintf(out, "Plugin-Metadata verifijert: %s\n", verification.FileName)
	}

	return nil
}
