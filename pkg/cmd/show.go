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

const showDesc = `
Düssen Befehl bestäht us mehreren Unterbefehlen, to Informatsjonen över eene Chart antoseegen
`

const showAllDesc = `
Düssen Befehl inspekjert eene Chart (Verzeichnis, Datei oder URL) un zeeget all sienen Inhalt
(values.yaml, Chart.yaml, README)
`

const showValuesDesc = `
Düssen Befehl inspekjert eene Chart (Verzeichnis, Datei oder URL) un zeeget den Inhalt
von de values.yaml-Datei
`

const showChartDesc = `
Düssen Befehl inspekjert eene Chart (Verzeichnis, Datei oder URL) un zeeget den Inhalt
von de Chart.yaml-Datei
`

const readmeChartDesc = `
Düssen Befehl inspekjert eene Chart (Verzeichnis, Datei oder URL) un zeeget den Inhalt
von de README-Datei
`

const showCRDsDesc = `
Düssen Befehl inspekjert eene Chart (Verzeichnis, Datei oder URL) un zeeget den Inhalt
von de CustomResourceDefinition-Datein
`

func newShowCmd(cfg *action.Configuration, out io.Writer) *cobra.Command {
	client := action.NewShow(action.ShowAll, cfg)

	showCommand := &cobra.Command{
		Use:     "show",
		Short:   "zeegen Sie Informatsjonen von eene Chart",
		Aliases: []string{"inspect"},
		Long:    showDesc,
		Args:    require.NoArgs,
	}

	// Function providing dynamic auto-completion
	validArgsFunc := func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return noMoreArgsComp()
		}
		return compListCharts(toComplete, true)
	}

	all := &cobra.Command{
		Use:               "all [CHART]",
		Short:             "zeegen Sie alle Informatsjonen von de Chart",
		Long:              showAllDesc,
		Args:              require.ExactArgs(1),
		ValidArgsFunction: validArgsFunc,
		RunE: func(_ *cobra.Command, args []string) error {
			client.OutputFormat = action.ShowAll
			err := addRegistryClient(client)
			if err != nil {
				return err
			}
			output, err := runShow(args, client)
			if err != nil {
				return err
			}
			fmt.Fprint(out, output)
			return nil
		},
	}

	valuesSubCmd := &cobra.Command{
		Use:               "values [CHART]",
		Short:             "zeegen Sie de Werten von de Chart",
		Long:              showValuesDesc,
		Args:              require.ExactArgs(1),
		ValidArgsFunction: validArgsFunc,
		RunE: func(_ *cobra.Command, args []string) error {
			client.OutputFormat = action.ShowValues
			err := addRegistryClient(client)
			if err != nil {
				return err
			}
			output, err := runShow(args, client)
			if err != nil {
				return err
			}
			fmt.Fprint(out, output)
			return nil
		},
	}

	chartSubCmd := &cobra.Command{
		Use:               "chart [CHART]",
		Short:             "zeegen Sie de Definition von de Chart",
		Long:              showChartDesc,
		Args:              require.ExactArgs(1),
		ValidArgsFunction: validArgsFunc,
		RunE: func(_ *cobra.Command, args []string) error {
			client.OutputFormat = action.ShowChart
			err := addRegistryClient(client)
			if err != nil {
				return err
			}
			output, err := runShow(args, client)
			if err != nil {
				return err
			}
			fmt.Fprint(out, output)
			return nil
		},
	}

	readmeSubCmd := &cobra.Command{
		Use:               "readme [CHART]",
		Short:             "zeegen Sie de README von de Chart",
		Long:              readmeChartDesc,
		Args:              require.ExactArgs(1),
		ValidArgsFunction: validArgsFunc,
		RunE: func(_ *cobra.Command, args []string) error {
			client.OutputFormat = action.ShowReadme
			err := addRegistryClient(client)
			if err != nil {
				return err
			}
			output, err := runShow(args, client)
			if err != nil {
				return err
			}
			fmt.Fprint(out, output)
			return nil
		},
	}

	crdsSubCmd := &cobra.Command{
		Use:               "crds [CHART]",
		Short:             "zeegen Sie de CRDs von de Chart",
		Long:              showCRDsDesc,
		Args:              require.ExactArgs(1),
		ValidArgsFunction: validArgsFunc,
		RunE: func(_ *cobra.Command, args []string) error {
			client.OutputFormat = action.ShowCRDs
			err := addRegistryClient(client)
			if err != nil {
				return err
			}
			output, err := runShow(args, client)
			if err != nil {
				return err
			}
			fmt.Fprint(out, output)
			return nil
		},
	}

	cmds := []*cobra.Command{all, readmeSubCmd, valuesSubCmd, chartSubCmd, crdsSubCmd}
	for _, subCmd := range cmds {
		addShowFlags(subCmd, client)
		showCommand.AddCommand(subCmd)
	}

	return showCommand
}

func addShowFlags(subCmd *cobra.Command, client *action.Show) {
	f := subCmd.Flags()

	f.BoolVar(&client.Devel, "devel", false, "bruken Sie ook Entwicklungsversjonen. Entspricht Versjon '>0.0.0-0'. Wan --version jesett es, werd dütt ijgnoriert")
	if subCmd.Name() == "values" {
		f.StringVar(&client.JSONPathTemplate, "jsonpath", "", "jewen Sie eenen JSONPath-Usdruck to de Utgawe to filteren")
	}
	addChartPathOptionsFlags(f, &client.ChartPathOptions)

	err := subCmd.RegisterFlagCompletionFunc("version", func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 1 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return compVersionFlag(args[0], toComplete)
	})

	if err != nil {
		log.Fatal(err)
	}
}

func runShow(args []string, client *action.Show) (string, error) {
	slog.Debug("original chart version", "version", client.Version)
	if client.Version == "" && client.Devel {
		slog.Debug("setting version to >0.0.0-0")
		client.Version = ">0.0.0-0"
	}

	cp, err := client.LocateChart(args[0], settings)
	if err != nil {
		return "", err
	}
	return client.Run(cp)
}

func addRegistryClient(client *action.Show) error {
	registryClient, err := newRegistryClient(client.CertFile, client.KeyFile, client.CaFile,
		client.InsecureSkipTLSVerify, client.PlainHTTP, client.Username, client.Password)
	if err != nil {
		return fmt.Errorf("Registry-Client fehlt: %w", err)
	}
	client.SetRegistryClient(registryClient)
	return nil
}
