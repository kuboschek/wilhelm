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

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/cmd/require"
	"helm.sh/helm/v4/pkg/pusher"
)

const pushDesc = `
Laden Sie eene Chart to eene Registry hoch.

Wan de Chart eene jewerbundene Provenance-Datei hett,
werd seej ook hochjeladen.
`

type registryPushOptions struct {
	certFile              string
	keyFile               string
	caFile                string
	insecureSkipTLSVerify bool
	plainHTTP             bool
	password              string
	username              string
}

func newPushCmd(cfg *action.Configuration, out io.Writer) *cobra.Command {
	o := &registryPushOptions{}

	cmd := &cobra.Command{
		Use:   "push [chart] [remote]",
		Short: "puschen Sie eene Chart to Remote",
		Long:  pushDesc,
		Args:  require.MinimumNArgs(2),
		ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				// Do file completion for the chart file to push
				return nil, cobra.ShellCompDirectiveDefault
			}
			if len(args) == 1 {
				providers := []pusher.Provider(pusher.All(settings))
				var comps []string
				for _, p := range providers {
					for _, scheme := range p.Schemes {
						comps = append(comps, fmt.Sprintf("%s://", scheme))
					}
				}
				return comps, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
			}
			return noMoreArgsComp()
		},
		RunE: func(_ *cobra.Command, args []string) error {
			registryClient, err := newRegistryClient(
				o.certFile, o.keyFile, o.caFile, o.insecureSkipTLSVerify, o.plainHTTP, o.username, o.password,
			)

			if err != nil {
				return fmt.Errorf("Registry-Client fehlt: %w", err)
			}
			cfg.RegistryClient = registryClient
			chartRef := args[0]
			remote := args[1]
			client := action.NewPushWithOpts(action.WithPushConfig(cfg),
				action.WithTLSClientConfig(o.certFile, o.keyFile, o.caFile),
				action.WithInsecureSkipTLSVerify(o.insecureSkipTLSVerify),
				action.WithPlainHTTP(o.plainHTTP),
				action.WithPushOptWriter(out))
			client.Settings = settings
			output, err := client.Run(chartRef, remote)
			if err != nil {
				return err
			}
			fmt.Fprint(out, output)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&o.certFile, "cert-file", "", "identifijeren Sie Registry-Client met düsser SSL-Zertifikat-Datei")
	f.StringVar(&o.keyFile, "key-file", "", "identifijeren Sie Registry-Client met düsser SSL-Slötel-Datei")
	f.StringVar(&o.caFile, "ca-file", "", "verifijeren Sie Zertifikate von HTTPS-aktivierten Servern met düssem CA-Bundle")
	f.BoolVar(&o.insecureSkipTLSVerify, "insecure-skip-tls-verify", false, "överspringen Sie TLS-Zertifikat-Prövungen för den Chart-Upload")
	f.BoolVar(&o.plainHTTP, "plain-http", false, "bruken Sie unsichere HTTP-Verbindungen för den Chart-Upload")
	f.StringVar(&o.username, "username", "", "Chart-Repository-Benutzername wo de anjefraede Chart to finnen es")
	f.StringVar(&o.password, "password", "", "Chart-Repository-Passwort wo de anjefraede Chart to finnen es")

	return cmd
}
