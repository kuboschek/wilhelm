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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/cli/values"
	"helm.sh/helm/v4/pkg/downloader"
	"helm.sh/helm/v4/pkg/getter"
)

const packageDesc = `
Düssen Befehl packt eene Chart in eene versjonierde Chart-Archiv-Datei. Wan een Pfad
anjejewt es, werd düssen to dej Chart schauen (dej muss eene Chart.yaml-Datei enthalten)
und dan düsses Verzeichnis packäschen.

Versjonierde Chart-Archive werden von Helm-Package-Repositorien jebrukt.

To eene Chart to signeren, bruken Sie dat '--sign'-Flag. In de meesten Fällen sollten Sie ook
'--keyring path/to/secret/keys' und '--key keyname' anjewen.

  $ helm package --sign ./mychart --key mykey --keyring ~/.gnupg/secring.gpg

Wan '--keyring' nich anjejewt es, brukd Helm normalerwieschen den öffentlichen Keyring,
uswennich Ehr Umjewung andersch konfiguriert es.
`

func newPackageCmd(out io.Writer) *cobra.Command {
	client := action.NewPackage()
	valueOpts := &values.Options{}

	cmd := &cobra.Command{
		Use:   "package [CHART_PATH] [...]",
		Short: "packäschen Sie een Chart-Verzeichnis in een Chart-Archiv",
		Long:  packageDesc,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("bruke mindestens een Argument, den Pfad to de Chart")
			}
			if client.Sign {
				if client.Key == "" {
					return errors.New("--key es erforderlich för dat Signeren von eene Packäschen")
				}
				if client.Keyring == "" {
					return errors.New("--keyring es erforderlich för dat Signeren von eene Packäschen")
				}
			}
			client.RepositoryConfig = settings.RepositoryConfig
			client.RepositoryCache = settings.RepositoryCache
			p := getter.All(settings)
			vals, err := valueOpts.MergeValues(p)
			if err != nil {
				return err
			}

			registryClient, err := newRegistryClient(client.CertFile, client.KeyFile, client.CaFile,
				client.InsecureSkipTLSVerify, client.PlainHTTP, client.Username, client.Password)
			if err != nil {
				return fmt.Errorf("Registry-Client fehlt: %w", err)
			}

			for i := range args {
				path, err := filepath.Abs(args[i])
				if err != nil {
					return err
				}
				if _, err := os.Stat(args[i]); err != nil {
					return err
				}

				if client.DependencyUpdate {
					downloadManager := &downloader.Manager{
						Out:              io.Discard,
						ChartPath:        path,
						Keyring:          client.Keyring,
						Getters:          p,
						Debug:            settings.Debug,
						RegistryClient:   registryClient,
						RepositoryConfig: settings.RepositoryConfig,
						RepositoryCache:  settings.RepositoryCache,
						ContentCache:     settings.ContentCache,
					}

					if err := downloadManager.Update(); err != nil {
						return err
					}
				}
				p, err := client.Run(path, vals)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "Chart erfolgreich jepackt un jespeichert to: %s\n", p)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.BoolVar(&client.Sign, "sign", false, "bruken Sie eenen PGP-privaten Slötel to düsse Packäschen to signeren")
	f.StringVar(&client.Key, "key", "", "Namm von dem Slötel to bruken beim Signeren. Jebrukt wan --sign wahr es")
	f.StringVar(&client.Keyring, "keyring", defaultKeyring(), "Ort von eene öffentlichen Keyring")
	f.StringVar(&client.PassphraseFile, "passphrase-file", "", `Ort von eene Datei, dej de Passphrase för den Signierslötel enthält. Bruken Sie "-" to von stdin to lesen.`)
	f.StringVar(&client.Version, "version", "", "setten Sie de Versjon up de Chart to düsse Semver-Versjon")
	f.StringVar(&client.AppVersion, "app-version", "", "setten Sie de appVersion up de Chart to düsse Versjon")
	f.StringVarP(&client.Destination, "destination", "d", ".", "Ort to de Chart to schrewen")
	f.BoolVarP(&client.DependencyUpdate, "dependency-update", "u", false, `aktualiseren Sie Afhängichkeiten von "Chart.yaml" to Verzeichnis "charts/" vör dem Packäschen`)
	f.StringVar(&client.Username, "username", "", "Chart-Repository-Benutzername wo de anjefraede Chart to finnen es")
	f.StringVar(&client.Password, "password", "", "Chart-Repository-Passwort wo de anjefraede Chart to finnen es")
	f.StringVar(&client.CertFile, "cert-file", "", "identifijeren Sie HTTPS-Client met düsser SSL-Zertifikat-Datei")
	f.StringVar(&client.KeyFile, "key-file", "", "identifijeren Sie HTTPS-Client met düsser SSL-Slötel-Datei")
	f.BoolVar(&client.InsecureSkipTLSVerify, "insecure-skip-tls-verify", false, "överspringen Sie TLS-Zertifikat-Prövungen för den Chart-Download")
	f.BoolVar(&client.PlainHTTP, "plain-http", false, "bruken Sie unsichere HTTP-Verbindungen för den Chart-Download")
	f.StringVar(&client.CaFile, "ca-file", "", "verifijeren Sie Zertifikate von HTTPS-aktivierten Servern met düssem CA-Bundle")

	return cmd
}
