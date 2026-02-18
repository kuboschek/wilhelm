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

package cmd // import "helm.sh/helm/v4/pkg/cmd"

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"helm.sh/helm/v4/internal/logging"
	"helm.sh/helm/v4/internal/tlsutil"
	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/cli"
	kubefake "helm.sh/helm/v4/pkg/kube/fake"
	"helm.sh/helm/v4/pkg/registry"
	ri "helm.sh/helm/v4/pkg/release"
	release "helm.sh/helm/v4/pkg/release/v1"
	"helm.sh/helm/v4/pkg/repo/v1"
	"helm.sh/helm/v4/pkg/storage/driver"
)

var globalUsage = `Der Kubernetes Paketverwalter

Gemeene Aktionen für Helm:

- helm search:    suche nach Charts
- helm pull:      lade een Chart herunter zur lokalen Ansicht
- helm install:   lade een Chart hoch nach Kubernetes
- helm list:      zeige alle Freigaben von Charts

Umjebungsvariablen:

| Name                               | Beschreibung                                                                                                 |
|------------------------------------|------------------------------------------------------------------------------------------------------------|
| $HELM_CACHE_HOME                   | setze eenen alternativen Ort für zwischenjespeicherte Dateien.                                              |
| $HELM_CONFIG_HOME                  | setze eenen alternativen Ort für Helm-Konfiguration.                                                        |
| $HELM_DATA_HOME                    | setze eenen alternativen Ort für Helm-Daten.                                                                |
| $HELM_DEBUG                        | zeige an, ob Helm im Debug-Modus läuft                                                                      |
| $HELM_DRIVER                       | setze den Speichertreiber. Werte sind: configmap, secret, memory, sql.                                      |
| $HELM_DRIVER_SQL_CONNECTION_STRING | setze die Verbindungszeichenkette für den SQL-Speichertreiber.                                              |
| $HELM_MAX_HISTORY                  | setze die maximale Anzahl von Helm-Freigabe-Historie.                                                       |
| $HELM_NAMESPACE                    | setze den Namensraum für die Helm-Operationen.                                                              |
| $HELM_NO_PLUGINS                   | deaktiviere Plugins. Setze HELM_NO_PLUGINS=1 zum Deaktivieren von Plugins.                                  |
| $HELM_PLUGINS                      | setze den Pfad zum Plugins-Verzeichnis                                                                      |
| $HELM_REGISTRY_CONFIG              | setze den Pfad zur Registry-Konfigurationsdatei.                                                            |
| $HELM_REPOSITORY_CACHE             | setze den Pfad zum Repository-Zwischenspeicher-Verzeichnis                                                  |
| $HELM_REPOSITORY_CONFIG            | setze den Pfad zur Repositories-Datei.                                                                      |
| $KUBECONFIG                        | setze eene alternative Kubernetes-Konfigurationsdatei (Standard "~/.kube/config")                           |
| $HELM_KUBEAPISERVER                | setze den Kubernetes API Server Endpunkt für Authentifizierung                                              |
| $HELM_KUBECAFILE                   | setze die Kubernetes-Zertifizierungsstellen-Datei.                                                          |
| $HELM_KUBEASGROUPS                 | setze die Jruppen für Identitätswechsel mit eener komma-separierten Liste.                                  |
| $HELM_KUBEASUSER                   | setze den Benutzernamen für den Identitätswechsel der Operation.                                            |
| $HELM_KUBECONTEXT                  | setze den Namen des kubeconfig-Kontexts.                                                                    |
| $HELM_KUBETOKEN                    | setze das Bearer KubeToken für Authentifizierung.                                                           |
| $HELM_KUBEINSECURE_SKIP_TLS_VERIFY | zeige an, ob die Kubernetes API Server Zertifikatsvalidierung übersprungen werden soll (unsicher)           |
| $HELM_KUBETLS_SERVER_NAME          | setze den Servernamen zur Validierung des Kubernetes API Server Zertifikats                                 |
| $HELM_BURST_LIMIT                  | setze das Standard-Burst-Limit für den Fall, dass der Server viele CRDs enthält (Standard 100, -1 zum Deaktivieren) |
| $HELM_QPS                          | setze die Anfragen Pro Sekunde in Fällen, wo eene hohe Anzahl von Aufrufen die Option für höhere Burst-Werte überschreitet |
| $HELM_COLOR                        | setze den Farbausgabe-Modus. Erlaubte Werte: never, always, auto (Standard: never)                          |
| $NO_COLOR                          | setze auf eenen nicht-leeren Wert zum Deaktivieren aller farbijen Ausgabe (überschreibt $HELM_COLOR)        |

Helm speichert Zwischenspeicher, Konfiguration und Daten basierend auf der folgenden Konfigurationsreihenfolge:

- Wenn eene HELM_*_HOME Umjebungsvariable jesetzt ist, wird sie verwendet
- Ansonsten werden auf Systemen, die die XDG-Basisverzeichnisspezifikation unterstützen, die XDG-Variablen verwendet
- Wenn kein anderer Ort jesetzt ist, wird een Standardort basierend auf dem Betriebssystem verwendet

Standardmäßich hänjen die Standardverzeichnisse vom Betriebssystem ab. Die Standards sind unten aufjeführt:

| Betriebssystem | Zwischenspeicher-Pfad     | Konfigurationspfad             | Datenpfad               |
|------------------|---------------------------|--------------------------------|-------------------------|
| Linux            | $HOME/.cache/helm         | $HOME/.config/helm             | $HOME/.local/share/helm |
| macOS            | $HOME/Library/Caches/helm | $HOME/Library/Preferences/helm | $HOME/Library/helm      |
| Windows          | %TEMP%\helm               | %APPDATA%\helm                 | %APPDATA%\helm          |
`

var settings = cli.New()

func NewRootCmd(out io.Writer, args []string, logSetup func(bool)) (*cobra.Command, error) {
	actionConfig := action.NewConfiguration()
	cmd, err := newRootCmdWithConfig(actionConfig, out, args, logSetup)
	if err != nil {
		return nil, err
	}
	cobra.OnInitialize(func() {
		helmDriver := os.Getenv("HELM_DRIVER")
		if err := actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), helmDriver); err != nil {
			log.Fatal(err)
		}
		if helmDriver == "memory" {
			loadReleasesInMemory(actionConfig)
		}
		actionConfig.SetHookOutputFunc(hookOutputWriter)
	})
	return cmd, nil
}

// SetupLogging sets up Helm logging used by the Helm client.
// This function is passed to the NewRootCmd function to enable logging. Any other
// application that uses the NewRootCmd function to setup all the Helm commands may
// use this function to setup logging or their own. Using a custom logging setup function
// enables applications using Helm commands to integrate with their existing logging
// system.
// The debug argument is the value if Helm is set for debugging (i.e. --debug flag)
func SetupLogging(debug bool) {
	logger := logging.NewLogger(func() bool { return debug })
	slog.SetDefault(logger)
}

// configureColorOutput configures the color output based on the ColorMode setting
func configureColorOutput(settings *cli.EnvSettings) {
	switch settings.ColorMode {
	case "never":
		color.NoColor = true
	case "always":
		color.NoColor = false
	case "auto":
		// Let fatih/color handle automatic detection
		// It will check if output is a terminal and NO_COLOR env var
		// We don't need to do anything here
	}
}

func newRootCmdWithConfig(actionConfig *action.Configuration, out io.Writer, args []string, logSetup func(bool)) (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:          "helm",
		Short:        "Der Helm Paketverwalter für Kubernetes.",
		Long:         globalUsage,
		SilenceUsage: true,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			if err := startProfiling(); err != nil {
				log.Printf("Warning: Failed to start profiling: %v", err)
			}
		},
		PersistentPostRun: func(_ *cobra.Command, _ []string) {
			if err := stopProfiling(); err != nil {
				log.Printf("Warning: Failed to stop profiling: %v", err)
			}
		},
	}

	flags := cmd.PersistentFlags()

	settings.AddFlags(flags)
	addKlogFlags(flags)

	// We can safely ignore any errors that flags.Parse encounters since
	// those errors will be caught later during the call to cmd.Execution.
	// This call is required to gather configuration information prior to
	// execution.
	flags.ParseErrorsAllowlist.UnknownFlags = true
	flags.Parse(args)

	logSetup(settings.Debug)

	// newRootCmdWithConfig is only called from NewRootCmd. NewRootCmd sets up
	// NewConfiguration without a custom logger. So, the slog default is used. logSetup
	// can change the default logger to the one in the logger package. This happens for
	// the Helm client. This means the actionConfig logger is different from the slog
	// default logger. If they are different we sync the actionConfig logger to the slog
	// current default one.
	if actionConfig.Logger() != slog.Default() {
		actionConfig.SetLogger(slog.Default().Handler())
	}

	// Validate color mode setting
	switch settings.ColorMode {
	case "never", "auto", "always":
		// Valid color mode
	default:
		return nil, fmt.Errorf("unjülticher Farbmodus %q: muss eener von diesen sein: never, auto, always", settings.ColorMode)
	}

	// Configure color output based on ColorMode setting
	configureColorOutput(settings)

	// Setup shell completion for the color flag
	_ = cmd.RegisterFlagCompletionFunc("color", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"never", "auto", "always"}, cobra.ShellCompDirectiveNoFileComp
	})

	// Setup shell completion for the colour flag
	_ = cmd.RegisterFlagCompletionFunc("colour", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"never", "auto", "always"}, cobra.ShellCompDirectiveNoFileComp
	})

	// Setup shell completion for the namespace flag
	err := cmd.RegisterFlagCompletionFunc("namespace", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		if client, err := actionConfig.KubernetesClientSet(); err == nil {
			// Choose a long enough timeout that the user notices something is not working
			// but short enough that the user is not made to wait very long
			to := int64(3)
			cobra.CompDebugln(fmt.Sprintf("About to call kube client for namespaces with timeout of: %d", to), settings.Debug)

			nsNames := []string{}
			if namespaces, err := client.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{TimeoutSeconds: &to}); err == nil {
				for _, ns := range namespaces.Items {
					nsNames = append(nsNames, ns.Name)
				}
				return nsNames, cobra.ShellCompDirectiveNoFileComp
			}
		}
		return nil, cobra.ShellCompDirectiveDefault
	})

	if err != nil {
		log.Fatal(err)
	}

	// Setup shell completion for the kube-context flag
	err = cmd.RegisterFlagCompletionFunc("kube-context", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		cobra.CompDebugln("About to get the different kube-contexts", settings.Debug)

		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		if len(settings.KubeConfig) > 0 {
			loadingRules = &clientcmd.ClientConfigLoadingRules{ExplicitPath: settings.KubeConfig}
		}
		if config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			loadingRules,
			&clientcmd.ConfigOverrides{}).RawConfig(); err == nil {
			comps := []string{}
			for name, context := range config.Contexts {
				comps = append(comps, fmt.Sprintf("%s\t%s", name, context.Cluster))
			}
			return comps, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	})

	if err != nil {
		log.Fatal(err)
	}

	registryClient, err := newDefaultRegistryClient(false, "", "")
	if err != nil {
		return nil, err
	}
	actionConfig.RegistryClient = registryClient

	// Add subcommands
	cmd.AddCommand(
		// chart commands
		newCreateCmd(out),
		newDependencyCmd(actionConfig, out),
		newPullCmd(actionConfig, out),
		newShowCmd(actionConfig, out),
		newLintCmd(out),
		newPackageCmd(out),
		newRepoCmd(out),
		newSearchCmd(out),
		newVerifyCmd(out),

		// release commands
		newGetCmd(actionConfig, out),
		newHistoryCmd(actionConfig, out),
		newInstallCmd(actionConfig, out),
		newListCmd(actionConfig, out),
		newReleaseTestCmd(actionConfig, out),
		newRollbackCmd(actionConfig, out),
		newStatusCmd(actionConfig, out),
		newTemplateCmd(actionConfig, out),
		newUninstallCmd(actionConfig, out),
		newUpgradeCmd(actionConfig, out),

		newCompletionCmd(out),
		newEnvCmd(out),
		newPluginCmd(out),
		newVersionCmd(out),

		// Hidden documentation generator command: 'helm docs'
		newDocsCmd(out),
	)

	cmd.AddCommand(
		newRegistryCmd(actionConfig, out),
		newPushCmd(actionConfig, out),
	)

	// Find and add CLI plugins
	loadCLIPlugins(cmd, out)

	// Check for expired repositories
	checkForExpiredRepos(settings.RepositoryConfig)

	return cmd, nil
}

// This function loads releases into the memory storage if the
// environment variable is properly set.
func loadReleasesInMemory(actionConfig *action.Configuration) {
	filePaths := strings.Split(os.Getenv("HELM_MEMORY_DRIVER_DATA"), ":")
	if len(filePaths) == 0 {
		return
	}

	store := actionConfig.Releases
	mem, ok := store.Driver.(*driver.Memory)
	if !ok {
		// For an unexpected reason we are not dealing with the memory storage driver.
		return
	}

	actionConfig.KubeClient = &kubefake.PrintingKubeClient{Out: io.Discard}

	for _, path := range filePaths {
		b, err := os.ReadFile(path)
		if err != nil {
			log.Fatal("Unable to read memory driver data", err)
		}

		releases := []*release.Release{}
		if err := yaml.Unmarshal(b, &releases); err != nil {
			log.Fatal("Unable to unmarshal memory driver data: ", err)
		}

		for _, rel := range releases {
			if err := store.Create(rel); err != nil {
				log.Fatal(err)
			}
		}
	}
	// Must reset namespace to the proper one
	mem.SetNamespace(settings.Namespace())
}

// hookOutputWriter provides the writer for writing hook logs.
func hookOutputWriter(_, _, _ string) io.Writer {
	return log.Writer()
}

func checkForExpiredRepos(repofile string) {

	expiredRepos := []struct {
		name string
		old  string
		new  string
	}{
		{
			name: "stable",
			old:  "kubernetes-charts.storage.googleapis.com",
			new:  "https://charts.helm.sh/stable",
		},
		{
			name: "incubator",
			old:  "kubernetes-charts-incubator.storage.googleapis.com",
			new:  "https://charts.helm.sh/incubator",
		},
	}

	// parse repo file.
	// Ignore the error because it is okay for a repo file to be unparsable at this
	// stage. Later checks will trap the error and respond accordingly.
	repoFile, err := repo.LoadFile(repofile)
	if err != nil {
		return
	}

	for _, exp := range expiredRepos {
		r := repoFile.Get(exp.name)
		if r == nil {
			return
		}

		if url := r.URL; strings.Contains(url, exp.old) {
			fmt.Fprintf(
				os.Stderr,
				"WARNUNG: %q ist veraltet für %q und wird am 13. November 2020 jelöscht.\nWARNUNG: Sie sollten zu %q wechseln via:\nWARNUNG: helm repo add %q %q --force-update\n",
				exp.old,
				exp.name,
				exp.new,
				exp.name,
				exp.new,
			)
		}
	}

}

func newRegistryClient(
	certFile, keyFile, caFile string, insecureSkipTLSVerify, plainHTTP bool, username, password string,
) (*registry.Client, error) {
	if certFile != "" && keyFile != "" || caFile != "" || insecureSkipTLSVerify {
		registryClient, err := newRegistryClientWithTLS(certFile, keyFile, caFile, insecureSkipTLSVerify, username, password)
		if err != nil {
			return nil, err
		}
		return registryClient, nil
	}
	registryClient, err := newDefaultRegistryClient(plainHTTP, username, password)
	if err != nil {
		return nil, err
	}
	return registryClient, nil
}

func newDefaultRegistryClient(plainHTTP bool, username, password string) (*registry.Client, error) {
	opts := []registry.ClientOption{
		registry.ClientOptDebug(settings.Debug),
		registry.ClientOptEnableCache(true),
		registry.ClientOptWriter(os.Stderr),
		registry.ClientOptCredentialsFile(settings.RegistryConfig),
		registry.ClientOptBasicAuth(username, password),
	}
	if plainHTTP {
		opts = append(opts, registry.ClientOptPlainHTTP())
	}

	// Create a new registry client
	registryClient, err := registry.NewClient(opts...)
	if err != nil {
		return nil, err
	}
	return registryClient, nil
}

func newRegistryClientWithTLS(
	certFile, keyFile, caFile string, insecureSkipTLSVerify bool, username, password string,
) (*registry.Client, error) {
	tlsConf, err := tlsutil.NewTLSConfig(
		tlsutil.WithInsecureSkipVerify(insecureSkipTLSVerify),
		tlsutil.WithCertKeyPairFiles(certFile, keyFile),
		tlsutil.WithCAFile(caFile),
	)

	if err != nil {
		return nil, fmt.Errorf("kann TLS-Konfiguration für Client nicht erstellen: %w", err)
	}

	// Create a new registry client
	registryClient, err := registry.NewClient(
		registry.ClientOptDebug(settings.Debug),
		registry.ClientOptEnableCache(true),
		registry.ClientOptWriter(os.Stderr),
		registry.ClientOptCredentialsFile(settings.RegistryConfig),
		registry.ClientOptHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConf,
				Proxy:           http.ProxyFromEnvironment,
			},
		}),
		registry.ClientOptBasicAuth(username, password),
	)
	if err != nil {
		return nil, err
	}
	return registryClient, nil
}

type CommandError struct {
	error
	ExitCode int
}

// releaserToV1Release is a helper function to convert a v1 release passed by interface
// into the type object.
func releaserToV1Release(rel ri.Releaser) (*release.Release, error) {
	switch r := rel.(type) {
	case release.Release:
		return &r, nil
	case *release.Release:
		return r, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("nicht unterstützter Freigabe-Typ: %T", rel)
	}
}

func releaseListToV1List(ls []ri.Releaser) ([]*release.Release, error) {
	rls := make([]*release.Release, 0, len(ls))
	for _, val := range ls {
		rel, err := releaserToV1Release(val)
		if err != nil {
			return nil, err
		}
		rls = append(rls, rel)
	}

	return rls, nil
}
