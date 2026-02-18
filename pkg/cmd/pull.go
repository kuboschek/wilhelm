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
	"log"
	"log/slog"

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/cmd/require"
)

const pullDesc = `
Roopen Sie een Packäschen von eene Package-Repository und laden Sie et lokal herunner.

Dütt es nöttlich to Packäschen to holen, to inspekjeren, to änneren oder to repackäschen. Et kann
ook jebrukt werden, to kryptograafische Verifikation von eene Chart ustoföhren ohn de Chart
to installäschen.

Et jeft Optionen to de Chart na dem Download ustopacken. Dütt werd een
Verzeichnis för de Chart schöpen und in düsses Verzeichnis entkomprimieren.

Wan dat --verify-Flag anjejewt es, MUSS de anjefraede Chart eene Provenance-
Datei hebben un MUSS de Verifikationsprozess duurchstahn. Fähler in irjendeenen Deel von dütt werd
to eenen Fehler föhren, un de Chart werd nich lokal jespeichert.
`

func newPullCmd(cfg *action.Configuration, out io.Writer) *cobra.Command {
	client := action.NewPull(action.WithConfig(cfg))

	cmd := &cobra.Command{
		Use:     "pull [chart URL | repo/chartname] [...]",
		Short:   "laden Sie eene Chart von eene Repository herunner un (optional) packäschen Sie se in lokales Verzeichnis us",
		Aliases: []string{"fetch"},
		Long:    pullDesc,
		Args:    require.MinimumNArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return compListCharts(toComplete, false)
		},
		RunE: func(_ *cobra.Command, args []string) error {
			client.Settings = settings
			if client.Version == "" && client.Devel {
				slog.Debug("setting version to >0.0.0-0")
				client.Version = ">0.0.0-0"
			}

			registryClient, err := newRegistryClient(client.CertFile, client.KeyFile, client.CaFile,
				client.InsecureSkipTLSVerify, client.PlainHTTP, client.Username, client.Password)
			if err != nil {
				return fmt.Errorf("Registry-Client fehlt: %w", err)
			}
			client.SetRegistryClient(registryClient)

			for i := range args {
				output, err := client.Run(args[i])
				if err != nil {
					return err
				}
				fmt.Fprint(out, output)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.BoolVar(&client.Devel, "devel", false, "bruken Sie ook Entwicklungsversjonen. Entspricht Versjon '>0.0.0-0'. Wan --version jesett es, werd dütt ijgnoriert.")
	f.BoolVar(&client.Untar, "untar", false, "wan up wahr jesett, werd de Chart na dem Download entarrt")
	f.BoolVar(&client.VerifyLater, "prov", false, "holen Sie de Provenance-Datei, aber föhren Sie keene Verifikation us")
	f.StringVar(&client.UntarDir, "untardir", ".", "wan untar anjejewt es, spezifijert dütt Flag den Namm von dem Verzeichnis, in dat de Chart usjebredet werd")
	f.StringVarP(&client.DestDir, "destination", "d", ".", "Ort to de Chart to schrewen. Wan dütt un untardir anjejewt sünd, werd untardir to düssem anhangen")
	addChartPathOptionsFlags(f, &client.ChartPathOptions)

	err := cmd.RegisterFlagCompletionFunc("version", func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 1 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return compVersionFlag(args[0], toComplete)
	})

	if err != nil {
		log.Fatal(err)
	}

	return cmd
}
