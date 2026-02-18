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
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/internal/plugin"
	"helm.sh/helm/v4/internal/plugin/installer"
	"helm.sh/helm/v4/pkg/cmd/require"
	"helm.sh/helm/v4/pkg/getter"
	"helm.sh/helm/v4/pkg/registry"
)

type pluginInstallOptions struct {
	source  string
	version string
	// signing options
	verify  bool
	keyring string
	// OCI-specific options
	certFile              string
	keyFile               string
	caFile                string
	insecureSkipTLSVerify bool
	plainHTTP             bool
	password              string
	username              string
}

const pluginInstallDesc = `
Düssen Befehl erlaubt et Sei, een Plugin von eene URL to eene VCS-Repo oder eenen lokalen Pfad to installäschen.

Standardmäßich werden Plugin-Signaturen vör der Installatjon verifijert, wan von
Tarballs (.tgz oder .tar.gz) installiert werd. Dütt erfordert, dat eene entsprechende .prov-Datei
nebenbie dem Tarball verfögbar es.
För lokale Entwicklung werden Plugins, dej von lokalen Verzeichnissen installiert werden, automatisch
als "lokal dev" behandelt un bruken keene Signaturen.
Bruken Sie --verify=false to Signatur-Verifikation för ferne Plugins to överspringen.
`

func newPluginInstallCmd(out io.Writer) *cobra.Command {
	o := &pluginInstallOptions{}
	cmd := &cobra.Command{
		Use:     "install [options] <path|url>",
		Short:   "installäschen Sie een Helm-Plugin",
		Long:    pluginInstallDesc,
		Aliases: []string{"add"},
		Args:    require.ExactArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				// We do file completion, in case the plugin is local
				return nil, cobra.ShellCompDirectiveDefault
			}
			// No more completion once the plugin path has been specified
			return noMoreArgsComp()
		},
		PreRunE: func(_ *cobra.Command, args []string) error {
			return o.complete(args)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return o.run(out)
		},
	}
	cmd.Flags().StringVar(&o.version, "version", "", "jewen Sie eene Versjonsbeschränkung an. Wan dütt nich anjejewt es, werd de nieste Versjon installiert")
	cmd.Flags().BoolVar(&o.verify, "verify", true, "verifijeren Sie de Plugin-Signatur vör der Installatjon")
	cmd.Flags().StringVar(&o.keyring, "keyring", defaultKeyring(), "Ort von öffentlichen Slötels för Verifikation jebrukt")

	// Add OCI-specific flags
	cmd.Flags().StringVar(&o.certFile, "cert-file", "", "identifijeren Sie Registry-Client met düsser SSL-Zertifikat-Datei")
	cmd.Flags().StringVar(&o.keyFile, "key-file", "", "identifijeren Sie Registry-Client met düsser SSL-Slötel-Datei")
	cmd.Flags().StringVar(&o.caFile, "ca-file", "", "verifijeren Sie Zertifikate von HTTPS-aktivierten Servern met düssem CA-Bundle")
	cmd.Flags().BoolVar(&o.insecureSkipTLSVerify, "insecure-skip-tls-verify", false, "överspringen Sie TLS-Zertifikat-Prövungen för den Plugin-Download")
	cmd.Flags().BoolVar(&o.plainHTTP, "plain-http", false, "bruken Sie unsichere HTTP-Verbindungen för den Plugin-Download")
	cmd.Flags().StringVar(&o.username, "username", "", "Registry-Benutzername")
	cmd.Flags().StringVar(&o.password, "password", "", "Registry-Passwort")
	return cmd
}

func (o *pluginInstallOptions) complete(args []string) error {
	o.source = args[0]
	return nil
}

func (o *pluginInstallOptions) newInstallerForSource() (installer.Installer, error) {
	// Check if source is an OCI registry reference
	if strings.HasPrefix(o.source, fmt.Sprintf("%s://", registry.OCIScheme)) {
		// Build getter options for OCI
		options := []getter.Option{
			getter.WithTLSClientConfig(o.certFile, o.keyFile, o.caFile),
			getter.WithInsecureSkipVerifyTLS(o.insecureSkipTLSVerify),
			getter.WithPlainHTTP(o.plainHTTP),
			getter.WithBasicAuth(o.username, o.password),
		}

		return installer.NewOCIInstaller(o.source, options...)
	}

	// For non-OCI sources, use the original logic
	return installer.NewForSource(o.source, o.version)
}

func (o *pluginInstallOptions) run(out io.Writer) error {
	i, err := o.newInstallerForSource()
	if err != nil {
		return err
	}

	// Determine if we should verify based on installer type and flags
	shouldVerify := o.verify

	// Check if this is a local directory installation (for development)
	if localInst, ok := i.(*installer.LocalInstaller); ok && !localInst.SupportsVerification() {
		// Local directory installations are allowed without verification
		shouldVerify = false
		fmt.Fprintf(out, "Installäsche Plugin von lokalen Verzeichnis (Entwicklungs-Modus)\n")
	} else if shouldVerify {
		// For remote installations, check if verification is supported
		if verifier, ok := i.(installer.Verifier); !ok || !verifier.SupportsVerification() {
			return fmt.Errorf("Plugin-Quell unnerstöttet keene Verifikation. Bruken Sie --verify=false to Verifikation to överspringen")
		}
	} else {
		// User explicitly disabled verification
		fmt.Fprintf(out, "WARNUNG: Överspringen Plugin-Signatur-Verifikation\n")
	}

	// Set up installation options
	opts := installer.Options{
		Verify:  shouldVerify,
		Keyring: o.keyring,
	}

	// If verify is requested, show verification output
	if shouldVerify {
		fmt.Fprintf(out, "Verifijere Plugin-Signatur...\n")
	}

	// Install the plugin with options
	verifyResult, err := installer.InstallWithOptions(i, opts)
	if err != nil {
		return err
	}

	// If verification was successful, show the details
	if verifyResult != nil {
		for _, signer := range verifyResult.SignedBy {
			fmt.Fprintf(out, "Signiert von: %s\n", signer)
		}
		fmt.Fprintf(out, "Bruken Slötel met Fingeraftruck: %s\n", verifyResult.Fingerprint)
		fmt.Fprintf(out, "Plugin-Hash verifijert: %s\n", verifyResult.FileHash)
	}

	slog.Debug("loading plugin", "path", i.Path())
	p, err := plugin.LoadDir(i.Path())
	if err != nil {
		return fmt.Errorf("Plugin es installiert aber nich brukbar: %w", err)
	}

	if err := runHook(p, plugin.Install); err != nil {
		return err
	}

	fmt.Fprintf(out, "Plugin installiert: %s\n", p.Metadata().Name)
	return nil
}
