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
	"slices"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/pkg/cmd/require"
	"helm.sh/helm/v4/pkg/getter"
	"helm.sh/helm/v4/pkg/repo/v1"
)

const updateDesc = `
Update holt de nieuwesten Informatschonen övver Charts vun de jeweiligen Chart-Repositories.
Informatschonen warden lokal je-cachd, wo se vun Kommandos wie 'helm search' je-bruukt warden.

Jie könnt optional eene Liste vun Repositories angeben, de jie updaten wöllt.
	$ helm repo update <repo_name> ...
Öm alle Repositories to updaten, bruukt 'helm repo update'.
`

var errNoRepositories = errors.New("keene Repositories je-funnen. Jie müsst een addieren, bevör jie updaten könnt")

type repoUpdateOptions struct {
	update    func([]*repo.ChartRepository, io.Writer) error
	repoFile  string
	repoCache string
	names     []string
	timeout   time.Duration
}

func newRepoUpdateCmd(out io.Writer) *cobra.Command {
	o := &repoUpdateOptions{update: updateCharts}

	cmd := &cobra.Command{
		Use:     "update [REPO1 [REPO2 ...]]",
		Aliases: []string{"up"},
		Short:   "Informatschonen övver verfögbare Charts lokal vun Chart-Repositories updaten",
		Long:    updateDesc,
		Args:    require.MinimumNArgs(0),
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compListRepos(toComplete, args), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(_ *cobra.Command, args []string) error {
			o.repoFile = settings.RepositoryConfig
			o.repoCache = settings.RepositoryCache
			o.names = args
			return o.run(out)
		},
	}

	f := cmd.Flags()
	f.DurationVar(&o.timeout, "timeout", getter.DefaultHTTPTimeout*time.Second, "Tiet, de up den Download vun de Indexdatei to wachten is")

	return cmd
}

func (o *repoUpdateOptions) run(out io.Writer) error {
	f, err := repo.LoadFile(o.repoFile)
	switch {
	case isNotExist(err):
		return errNoRepositories
	case err != nil:
		return fmt.Errorf("Laden vun Datei je-feilt: %s: %w", o.repoFile, err)
	case len(f.Repositories) == 0:
		return errNoRepositories
	}

	var repos []*repo.ChartRepository
	updateAllRepos := len(o.names) == 0

	if !updateAllRepos {
		// Fail early if the user specified an invalid repo to update
		if err := checkRequestedRepos(o.names, f.Repositories); err != nil {
			return err
		}
	}

	for _, cfg := range f.Repositories {
		if updateAllRepos || isRepoRequested(cfg.Name, o.names) {
			r, err := repo.NewChartRepository(cfg, getter.All(settings, getter.WithTimeout(o.timeout)))
			if err != nil {
				return err
			}
			if o.repoCache != "" {
				r.CachePath = o.repoCache
			}
			repos = append(repos, r)
		}
	}

	return o.update(repos, out)
}

func updateCharts(repos []*repo.ChartRepository, out io.Writer) error {
	fmt.Fprintln(out, "Holt juch fast, wieldes wi dat Nieuweste vun jue Chart-Repositories holen...")
	var wg sync.WaitGroup
	failRepoURLChan := make(chan string, len(repos))

	writeMutex := sync.Mutex{}
	for _, re := range repos {
		wg.Add(1)
		go func(re *repo.ChartRepository) {
			defer wg.Done()
			if _, err := re.DownloadIndexFile(); err != nil {
				writeMutex.Lock()
				defer writeMutex.Unlock()
				fmt.Fprintf(out, "...Kann keen Update vun dat %q Chart-Repository (%s) kriegen:\n\t%s\n", re.Config.Name, re.Config.URL, err)
				failRepoURLChan <- re.Config.URL
			} else {
				writeMutex.Lock()
				defer writeMutex.Unlock()
				fmt.Fprintf(out, "...Erfolgreich een Update vun dat %q Chart-Repository je-holt\n", re.Config.Name)
			}
		}(re)
	}

	go func() {
		wg.Wait()
		close(failRepoURLChan)
	}()

	var repoFailList []string
	for url := range failRepoURLChan {
		repoFailList = append(repoFailList, url)
	}

	if len(repoFailList) > 0 {
		return fmt.Errorf("Update vun düsse Repositories je-feilt: %s",
			repoFailList)
	}

	fmt.Fprintln(out, "Update je-afsloten. ⎈Happy Helming!⎈")
	return nil
}

func checkRequestedRepos(requestedRepos []string, validRepos []*repo.Entry) error {
	for _, requestedRepo := range requestedRepos {
		found := false
		for _, repo := range validRepos {
			if requestedRepo == repo.Name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("keene Repositories je-funnen, de to '%s' passen. Nix ward je-updatet", requestedRepo)
		}
	}
	return nil
}

func isRepoRequested(repoName string, requestedRepos []string) bool {
	return slices.Contains(requestedRepos, repoName)
}
