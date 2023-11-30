// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aliacr

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	commonhttp "github.com/goharbor/harbor/src/common/http"
	"github.com/goharbor/harbor/src/common/utils"
	"github.com/goharbor/harbor/src/lib/log"
	adp "github.com/goharbor/harbor/src/pkg/reg/adapter"
	"github.com/goharbor/harbor/src/pkg/reg/adapter/native"
	"github.com/goharbor/harbor/src/pkg/reg/filter"
	"github.com/goharbor/harbor/src/pkg/reg/model"
	"github.com/goharbor/harbor/src/pkg/reg/util"
	"github.com/goharbor/harbor/src/pkg/registry/auth/bearer"
)

func init() {
	if err := adp.RegisterFactory(model.RegistryTypeAliAcr, new(factory)); err != nil {
		log.Errorf("failed to register factory for %s: %v", model.RegistryTypeAliAcr, err)
		return
	}
	log.Infof("the factory for adapter %s registered", model.RegistryTypeAliAcr)
}

// example:
// https://registry.%s.aliyuncs.com
// https://cr.%s.aliyuncs.com
// https://registry-vpc.%s.aliyuncs.com
// https://registry-internal.%s.aliyuncs.com
var regRegion = regexp.MustCompile(`https://(registry|cr|registry-vpc|registry-internal)\.([\w\-]+)\.aliyuncs\.com`)

// example:
// https://test-registry.%s.cr.aliyuncs.com
// https://test-registry-vpc.%s.cr.aliyuncs.com
var regEERegion = regexp.MustCompile(`https://[a-z0-9]+(?:[-][a-z0-9]+)*-(registry|registry-vpc)\.([\w\-]+)\.cr\.aliyuncs\.com`)

func getRegion(url string) (region string, err error) {
	if url == "" {
		return "", errors.New("empty url")
	}

	var rs []string
	if isACREE(url) {
		rs = regEERegion.FindStringSubmatch(url)
	} else {
		rs = regRegion.FindStringSubmatch(url)
	}
	if rs == nil {
		return "", errors.New("invalid Rgistry|CR service url")
	}
	// fmt.Println(rs)
	return rs[2], nil
}

func getInstanceId(url string, service string) string {
	if isACREE(url) {
		parts := strings.Split(service, ":")
		if len(parts) > 0 && strings.HasPrefix(parts[len(parts)-1], "cri-") {
			return parts[len(parts)-1]
		}
	}
	return ""
}

func isACREE(url string) bool {
	return strings.HasSuffix(url, registryACREESuffix)
}

func newAdapter(registry *model.Registry) (*adapter, error) {
	region, err := getRegion(registry.URL)
	if err != nil {
		return nil, err
	}
	isAcrEE := isACREE(registry.URL)
	var registryApi openapi
	var realm string
	var service string
	if !isAcrEE {
		switch true {
		case strings.Contains(registry.URL, "registry-vpc"):
			registry.URL = fmt.Sprintf(registryVPCEndpointTpl, region)
		case strings.Contains(registry.URL, "registry-internal"):
			registry.URL = fmt.Sprintf(registryInternalEndpointTpl, region)
		default:
			// fix url (allow user input cr service url)
			registry.URL = fmt.Sprintf(registryEndpointTpl, region)
		}

		realm, service, err = util.Ping(registry)
		if err != nil {
			return nil, err
		}
		registryApi, err = newAcrOpenapi(registry.Credential.AccessKey, registry.Credential.AccessSecret, region)
		if err != nil {
			return nil, err
		}
	} else {
		realm, service, err = util.Ping(registry)
		if err != nil {
			return nil, err
		}
		registryApi, err = newAcreeOpenapi(registry.Credential.AccessKey, registry.Credential.AccessSecret, region, getInstanceId(registry.URL, service))
	}
	authorizer := bearer.NewAuthorizer(realm, service, NewAuth(registryApi), commonhttp.GetHTTPTransport(commonhttp.WithInsecure(registry.Insecure)))
	return &adapter{
		registryApi: registryApi,
		registry:    registry,
		Adapter:     native.NewAdapterWithAuthorizer(registry, authorizer),
	}, nil
}

type factory struct {
}

// Create ...
func (f *factory) Create(r *model.Registry) (adp.Adapter, error) {
	return newAdapter(r)
}

// AdapterPattern ...
func (f *factory) AdapterPattern() *model.AdapterPattern {
	return getAdapterInfo()
}

var (
	_ adp.Adapter          = (*adapter)(nil)
	_ adp.ArtifactRegistry = (*adapter)(nil)
)

// adapter for to aliyun docker registry
type adapter struct {
	*native.Adapter
	registryApi openapi
	registry    *model.Registry
}

var _ adp.Adapter = &adapter{}

// Info ...
func (a *adapter) Info() (*model.RegistryInfo, error) {
	info := &model.RegistryInfo{
		Type: model.RegistryTypeAliAcr,
		SupportedResourceTypes: []string{
			model.ResourceTypeImage,
		},
		SupportedResourceFilters: []*model.FilterStyle{
			{
				Type:  model.FilterTypeName,
				Style: model.FilterStyleTypeText,
			},
			{
				Type:  model.FilterTypeTag,
				Style: model.FilterStyleTypeText,
			},
		},
		SupportedTriggers: []string{
			model.TriggerTypeManual,
			model.TriggerTypeScheduled,
		},
	}
	return info, nil
}

func getAdapterInfo() *model.AdapterPattern {
	var endpoints []*model.Endpoint
	// https://help.aliyun.com/document_detail/40654.html?spm=a2c4g.11186623.2.7.58683ae5Q4lo1o
	for _, e := range []string{
		"cn-qingdao",
		"cn-beijing",
		"cn-zhangjiakou",
		"cn-huhehaote",
		"cn-wulanchabu",
		"cn-hangzhou",
		"cn-shanghai",
		"cn-shenzhen",
		"cn-heyuan",
		"cn-guangzhou",
		"cn-chengdu",
		"cn-hongkong",
		"ap-southeast-1",
		"ap-southeast-2",
		"ap-southeast-3",
		"ap-southeast-5",
		"ap-south-1",
		"ap-northeast-1",
		"us-west-1",
		"us-east-1",
		"eu-central-1",
		"eu-west-1",
		"me-east-1",
	} {
		endpoints = append(endpoints, &model.Endpoint{
			Key:   e,
			Value: fmt.Sprintf("https://registry.%s.aliyuncs.com", e),
		})
		endpoints = append(endpoints, &model.Endpoint{
			Key:   e + "-vpc",
			Value: fmt.Sprintf("https://registry-vpc.%s.aliyuncs.com", e),
		})
		endpoints = append(endpoints, &model.Endpoint{
			Key:   e + "-internal",
			Value: fmt.Sprintf("https://registry-internal.%s.aliyuncs.com", e),
		})

		endpoints = append(endpoints, &model.Endpoint{
			Key:   e + "-ee-vpc",
			Value: fmt.Sprintf("https://instanceName-registry-vpc.%s.cr.aliyuncs.com", e),
		})

		endpoints = append(endpoints, &model.Endpoint{
			Key:   e + "-ee",
			Value: fmt.Sprintf("https://instanceName-registry.%s.cr.aliyuncs.com", e),
		})
	}
	info := &model.AdapterPattern{
		EndpointPattern: &model.EndpointPattern{
			EndpointType: model.EndpointPatternTypeList,
			Endpoints:    endpoints,
		},
	}
	return info
}

func (a *adapter) listCandidateNamespaces(namespacePattern string) ([]string, error) {
	var namespaces []string
	if len(namespacePattern) > 0 {
		if nms, ok := util.IsSpecificPathComponent(namespacePattern); ok {
			namespaces = append(namespaces, nms...)
		}
		if len(namespaces) > 0 {
			log.Debugf("parsed the namespaces %v from pattern %s", namespaces, namespacePattern)
			return namespaces, nil
		}
	}

	if a.registryApi == nil {
		return nil, errors.New("registry api is nil")
	}

	return a.registryApi.ListNamespace()
}

// FetchArtifacts AliACR not support /v2/_catalog of Registry, we'll list all resources via Aliyun's API
func (a *adapter) FetchArtifacts(filters []*model.Filter) ([]*model.Resource, error) {
	log.Debugf("FetchArtifacts.filters: %#v\n", filters)

	if a.registryApi == nil {
		return nil, errors.New("registryApi is nil")
	}

	var resources []*model.Resource
	// get filter pattern
	var repoPattern string
	var tagsPattern string
	for _, f := range filters {
		if f.Type == model.FilterTypeName {
			repoPattern = f.Value.(string)
		}
	}
	var namespacePattern = strings.Split(repoPattern, "/")[0]

	log.Debugf("\nrepoPattern=%s tagsPattern=%s\n\n", repoPattern, tagsPattern)

	// get namespaces
	namespaces, err := a.listCandidateNamespaces(namespacePattern)
	if err != nil {
		return nil, err
	}
	log.Debugf("got namespaces: %v \n", namespaces)

	// list repos
	var repositories []*repository
	for _, namespace := range namespaces {
		repos, err := a.registryApi.ListRepository(namespace)
		if err != nil {
			return nil, err
		}

		log.Debugf("\nnamespace: %s \t repositories: %#v\n\n", namespace, repos)

		for _, repo := range repos {
			var ok bool
			var repoName = filepath.Join(repo.Namespace, repo.Name)
			ok, err = util.Match(repoPattern, repoName)
			log.Debugf("\n Repository: %s\t repoPattern: %s\t Match: %v\n", repoName, repoPattern, ok)
			if err != nil {
				return nil, err
			}
			if ok {
				repositories = append(repositories, repo)
			}
		}
	}
	log.Debugf("FetchArtifacts.repositories: %#v\n", repositories)

	var rawResources = make([]*model.Resource, len(repositories))
	runner := utils.NewLimitedConcurrentRunner(adp.MaxConcurrency)

	for i, r := range repositories {
		index := i
		repo := r
		runner.AddTask(func() error {
			var tags []string
			tags, err = a.registryApi.ListRepoTag(repo)
			if err != nil {
				return fmt.Errorf("list tags for repo '%s' error: %v", repo.Name, err)
			}

			var artifacts []*model.Artifact
			for _, tag := range tags {
				artifacts = append(artifacts, &model.Artifact{
					Tags: []string{tag},
				})
			}
			filterArtifacts, err := filter.DoFilterArtifacts(artifacts, filters)
			if err != nil {
				return err
			}

			if len(filterArtifacts) > 0 {
				rawResources[index] = &model.Resource{
					Type:     model.ResourceTypeImage,
					Registry: a.registry,
					Metadata: &model.ResourceMetadata{
						Repository: &model.Repository{
							Name: filepath.Join(repo.Namespace, repo.Name),
						},
						Artifacts: filterArtifacts,
					},
				}
			}
			return nil
		})
	}
	if err = runner.Wait(); err != nil {
		return nil, fmt.Errorf("failed to fetch artifacts: %v", err)
	}
	for _, r := range rawResources {
		if r != nil {
			resources = append(resources, r)
		}
	}
	return resources, nil
}
