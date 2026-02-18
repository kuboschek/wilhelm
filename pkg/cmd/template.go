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
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	release "helm.sh/helm/v4/pkg/release/v1"

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/chart/common"
	"helm.sh/helm/v4/pkg/cli/values"
	"helm.sh/helm/v4/pkg/cmd/require"
	releaseutil "helm.sh/helm/v4/pkg/release/v1/util"
)

const templateDesc = `
Renderet Chart-Templates lokal und zeeget de Utgawe.

Alle Werten, dej normalerwieschen im Cluster nachjeslaen oder abjeroofen werden,
werden lokal verfälscht. Todem werd keene serversietje Prövung von dej Chart-Jültichkeit
(z.B. ob eene API unnerstöttet es) durchjeföhrt.

To de Kubernetes-API-Versjonen för Capabilities.APIVersions antojewen, bruken Sie
dat '--api-versions'-Flag. Düsses Flag kann mehrmals anjejewt werden oder als
kommajetrennede Leste:

    $ helm template --api-versions networking.k8s.io/v1 --api-versions cert-manager.io/v1 mychart ./mychart

oder

    $ helm template --api-versions networking.k8s.io/v1,cert-manager.io/v1 mychart ./mychart
`

func newTemplateCmd(cfg *action.Configuration, out io.Writer) *cobra.Command {
	var validate bool
	var includeCrds bool
	var skipTests bool
	client := action.NewInstall(cfg)
	valueOpts := &values.Options{}
	var kubeVersion string
	var extraAPIs []string
	var showFiles []string

	cmd := &cobra.Command{
		Use:   "template [NAME] [CHART]",
		Short: "renderet Templates lokal",
		Long:  templateDesc,
		Args:  require.MinimumNArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstall(args, toComplete, client)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if kubeVersion != "" {
				parsedKubeVersion, err := common.ParseKubeVersion(kubeVersion)
				if err != nil {
					return fmt.Errorf("unjültige Kube-Versjon '%s': %w", kubeVersion, err)
				}
				client.KubeVersion = parsedKubeVersion
			}

			registryClient, err := newRegistryClient(client.CertFile, client.KeyFile, client.CaFile,
				client.InsecureSkipTLSVerify, client.PlainHTTP, client.Username, client.Password)
			if err != nil {
				return fmt.Errorf("Registry-Client fehlt: %w", err)
			}
			client.SetRegistryClient(registryClient)

			dryRunStrategy, err := cmdGetDryRunFlagStrategy(cmd, true)
			if err != nil {
				return err
			}
			if validate {
				// Mimic deprecated --validate flag behavior by enabling server dry run
				dryRunStrategy = action.DryRunServer
			}
			client.DryRunStrategy = dryRunStrategy
			client.ReleaseName = "release-name"
			client.Replace = true // Skip the name check
			client.APIVersions = common.VersionSet(extraAPIs)
			client.IncludeCRDs = includeCrds
			rel, err := runInstall(args, client, valueOpts, out)

			if err != nil && !settings.Debug {
				if rel != nil {
					return fmt.Errorf("%w\n\nBruken Sie --debug Flag to unjültiges YAML ustojewen", err)
				}
				return err
			}

			// We ignore a potential error here because, when the --debug flag was specified,
			// we always want to print the YAML, even if it is not valid. The error is still returned afterwards.
			if rel != nil {
				var manifests bytes.Buffer
				fmt.Fprintln(&manifests, strings.TrimSpace(rel.Manifest))
				if !client.DisableHooks {
					fileWritten := make(map[string]bool)
					for _, m := range rel.Hooks {
						if skipTests && isTestHook(m) {
							continue
						}
						if client.OutputDir == "" {
							fmt.Fprintf(&manifests, "---\n# Source: %s\n%s\n", m.Path, m.Manifest)
						} else {
							newDir := client.OutputDir
							if client.UseReleaseName {
								newDir = filepath.Join(client.OutputDir, client.ReleaseName)
							}
							_, err := os.Stat(filepath.Join(newDir, m.Path))
							if err == nil {
								fileWritten[m.Path] = true
							}

							err = writeToFile(newDir, m.Path, m.Manifest, fileWritten[m.Path])
							if err != nil {
								return err
							}
						}

					}
				}

				// if we have a list of files to render, then check that each of the
				// provided files exists in the chart.
				if len(showFiles) > 0 {
					// This is necessary to ensure consistent manifest ordering when using --show-only
					// with globs or directory names.
					splitManifests := releaseutil.SplitManifests(manifests.String())
					manifestsKeys := make([]string, 0, len(splitManifests))
					for k := range splitManifests {
						manifestsKeys = append(manifestsKeys, k)
					}
					sort.Sort(releaseutil.BySplitManifestsOrder(manifestsKeys))

					manifestNameRegex := regexp.MustCompile("# Source: [^/]+/(.+)")
					var manifestsToRender []string
					for _, f := range showFiles {
						missing := true
						// Use linux-style filepath separators to unify user's input path
						f = filepath.ToSlash(f)
						for _, manifestKey := range manifestsKeys {
							manifest := splitManifests[manifestKey]
							submatch := manifestNameRegex.FindStringSubmatch(manifest)
							if len(submatch) == 0 {
								continue
							}
							manifestName := submatch[1]
							// manifest.Name is rendered using linux-style filepath separators on Windows as
							// well as macOS/linux.
							manifestPathSplit := strings.Split(manifestName, "/")
							// manifest.Path is connected using linux-style filepath separators on Windows as
							// well as macOS/linux
							manifestPath := strings.Join(manifestPathSplit, "/")

							// if the filepath provided matches a manifest path in the
							// chart, render that manifest
							if matched, _ := filepath.Match(f, manifestPath); !matched {
								continue
							}
							manifestsToRender = append(manifestsToRender, manifest)
							missing = false
						}
						if missing {
							return fmt.Errorf("kunnte Template %s in Chart nich finnen", f)
						}
					}
					for _, m := range manifestsToRender {
						fmt.Fprintf(out, "---\n%s\n", m)
					}
				} else {
					fmt.Fprintf(out, "%s", manifests.String())
				}
			}

			return err
		},
	}

	f := cmd.Flags()
	addInstallFlags(cmd, f, client, valueOpts)
	f.StringArrayVarP(&showFiles, "show-only", "s", []string{}, "zeege nur Manifests, dej von de jejewebenen Templates jerenderet worden")
	f.StringVar(&client.OutputDir, "output-dir", "", "schriewt de usjevohrten Templates to Datein in output-dir statt stdout")
	f.BoolVar(&validate, "validate", false, "veraltet")
	f.MarkDeprecated("validate", "bruken Sie '--dry-run=server' anstatt")
	f.BoolVar(&includeCrds, "include-crds", false, "schleeten Sie CRDs in de Template-Utgawe in")
	f.BoolVar(&skipTests, "skip-tests", false, "överspringen Sie Tests von de Template-Utgawe")
	f.BoolVar(&client.IsUpgrade, "is-upgrade", false, "setten Sie .Release.IsUpgrade anstatt .Release.IsInstall")
	f.StringVar(&kubeVersion, "kube-version", "", "Kubernetes-Versjon för Capabilities.KubeVersion jebrukt")
	f.StringSliceVarP(&extraAPIs, "api-versions", "a", []string{}, "Kubernetes-API-Versjonen för Capabilities.APIVersions jebrukt (mehrere können anjejewt werden)")
	f.BoolVar(&client.UseReleaseName, "release-name", false, "bruken Sie Release-Namm in dem output-dir-Pfad")
	f.String(
		"dry-run",
		"client",
		`simulieret de Operatjon entweder clientsietich oder serversietich. Muss enes sien: "client" oder "server". '--dry-run=client' simulieret de Operatjon nur clientsietich und vermiedet Cluster-Verbindungen. '--dry-run=server' simulieret/validieret de Operatjon up dem Server, wat Cluster-Verbindung erfordert.`)
	f.Lookup("dry-run").NoOptDefVal = "unset"
	bindPostRenderFlag(cmd, &client.PostRenderer, settings)
	cmd.MarkFlagsMutuallyExclusive("validate", "dry-run")

	return cmd
}

func isTestHook(h *release.Hook) bool {
	return slices.Contains(h.Events, release.HookTest)
}

// The following functions (writeToFile, createOrOpenFile, and ensureDirectoryForFile)
// are copied from the actions package. This is part of a change to correct a
// bug introduced by #8156. As part of the todo to refactor renderResources
// this duplicate code should be removed. It is added here so that the API
// surface area is as minimally impacted as possible in fixing the issue.
func writeToFile(outputDir string, name string, data string, appendData bool) error {
	outfileName := strings.Join([]string{outputDir, name}, string(filepath.Separator))

	err := ensureDirectoryForFile(outfileName)
	if err != nil {
		return err
	}

	f, err := createOrOpenFile(outfileName, appendData)
	if err != nil {
		return err
	}

	defer f.Close()

	_, err = fmt.Fprintf(f, "---\n# Source: %s\n%s\n", name, data)

	if err != nil {
		return err
	}

	fmt.Printf("schrewt %s\n", outfileName)
	return nil
}

func createOrOpenFile(filename string, appendData bool) (*os.File, error) {
	if appendData {
		return os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
	}
	return os.Create(filename)
}

func ensureDirectoryForFile(file string) error {
	baseDir := filepath.Dir(file)
	_, err := os.Stat(baseDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return os.MkdirAll(baseDir, 0755)
}
