// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"flag"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/AthenZ/athenz/clients/go/zms"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
)

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

func printVersion() {
	if VERSION == "" {
		fmt.Println("zms-authhistory (development version)")
	} else {
		fmt.Println("zms-authhistory " + VERSION + " " + BUILD_DATE)
	}
}

// ServiceDependency represents a dependency for a service
type ServiceDependency struct {
	Domain     string
	Service    string
	LastAccess string
}

// ServiceReport represents the report for a single service
type ServiceReport struct {
	ServiceName          string
	OutgoingDependencies []ServiceDependency
}

func main() {
	var domain, zmsURL, keyFile, certFile, caCertFile string
	var showVersion, domainsOnly bool
	var days int
	flag.StringVar(&domain, "domain", "", "domain name")
	flag.StringVar(&zmsURL, "zms", "", "ZMS server URL")
	flag.StringVar(&keyFile, "svc-key-file", "", "service identity private key file")
	flag.StringVar(&certFile, "svc-cert-file", "", "service identity certificate file")
	flag.StringVar(&caCertFile, "svc-cacert-file", "", "CA Certificates file")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.BoolVar(&domainsOnly, "domains-only", false, "For dependencies, only show the domain without the service name")
	flag.IntVar(&days, "days", 0, "Number of days to look back (ignore records older than this)")
	flag.Parse()

	if showVersion {
		printVersion()
		return
	}

	if domain == "" || zmsURL == "" || keyFile == "" || certFile == "" {
		log.Fatalln("usage: zms-authhistory -domain <domain> -zms <url> -svc-key-file <key-file> -svc-cert-file <cert-file> [-svc-cacert-file <ca-cert-file>] [-days <days>]")
	}

	// Create ZMS client with mTLS
	client, err := athenzutils.ZmsClient(zmsURL, keyFile, certFile, caCertFile, false)
	if err != nil {
		log.Fatalf("Failed to create ZMS client: %v", err)
	}

	// Call GetAuthHistoryDependencies API
	authHistory, err := client.GetAuthHistoryDependencies(zms.DomainName(domain))
	if err != nil {
		log.Fatalf("Failed to get auth history dependencies: %v", err)
	}

	// Process dependencies and generate report
	outgoing, incoming := processDependencies(domain, authHistory, days, domainsOnly)

	// Print report
	printReport(outgoing, incoming, domainsOnly)
}

func processDependencies(targetDomain string, authHistory *zms.AuthHistoryDependencies, days int, domainsOnly bool) (map[string]*ServiceReport, []ServiceDependency) {
	serviceReports := make(map[string]*ServiceReport)

	// Calculate cutoff time if days filter is specified
	var cutoffTime time.Time
	if days > 0 {
		cutoffTime = time.Now().UTC().AddDate(0, 0, -days)
	}

	// Process incoming dependencies
	incomingMap := make(map[string]ServiceDependency)

	if authHistory.IncomingDependencies != nil {
		for _, dep := range authHistory.IncomingDependencies {
			// Skip if timestamp is before cutoff
			if days > 0 && dep.Timestamp != nil {
				if dep.Timestamp.Time.Before(cutoffTime) {
					continue
				}
			}

			// Skip if the principal domain points back to itself
			if dep.PrincipalDomain == zms.DomainName(targetDomain) {
				continue
			}

			// Create unique key for deduplication: accessing service
			var depKey string
			if domainsOnly {
				depKey = string(dep.PrincipalDomain)
			} else {
				depKey = string(dep.PrincipalDomain) + "." + string(dep.PrincipalName)
			}

			// Keep the most recent entry if duplicate
			existing, exists := incomingMap[depKey]
			if !exists || (dep.Timestamp != nil && existing.LastAccess < dep.Timestamp.String()) {
				timestamp := ""
				if dep.Timestamp != nil {
					timestamp = dep.Timestamp.String()
				}
				incomingMap[depKey] = ServiceDependency{
					Domain:     string(dep.PrincipalDomain),
					Service:    string(dep.PrincipalName),
					LastAccess: timestamp,
				}
			}
		}
	}

	// Process outgoing dependencies
	// These are services from the target domain accessing resources in other domains
	// PrincipalDomain == targetDomain, PrincipalName is the service making the access
	outgoingMap := make(map[string]map[string]ServiceDependency)

	if authHistory.OutgoingDependencies != nil {
		for _, dep := range authHistory.OutgoingDependencies {
			// Skip if timestamp is before cutoff
			if days > 0 && dep.Timestamp != nil {
				if dep.Timestamp.Time.Before(cutoffTime) {
					continue
				}
			}

			if dep.PrincipalDomain == zms.DomainName(targetDomain) && dep.PrincipalName != "" {
				// Skip if the URI domain points back to itself
				if dep.UriDomain == zms.DomainName(targetDomain) {
					continue
				}
				serviceName := string(dep.PrincipalName)

				// Create unique key for deduplication: uriDomain
				depKey := string(dep.UriDomain)

				if outgoingMap[serviceName] == nil {
					outgoingMap[serviceName] = make(map[string]ServiceDependency)
				}

				// Keep the most recent entry if duplicate
				existing, exists := outgoingMap[serviceName][depKey]
				if !exists || (dep.Timestamp != nil && existing.LastAccess < dep.Timestamp.String()) {
					timestamp := ""
					if dep.Timestamp != nil {
						timestamp = dep.Timestamp.String()
					}
					outgoingMap[serviceName][depKey] = ServiceDependency{
						Domain:     string(dep.UriDomain),
						Service:    "", // For outgoing, we don't have a target service name
						LastAccess: timestamp,
					}
				}
			}
		}
	}

	// Build service reports
	for serviceName, outgoingDeps := range outgoingMap {
		if len(outgoingDeps) == 0 {
			continue
		}
		report := &ServiceReport{
			ServiceName:          serviceName,
			OutgoingDependencies: make([]ServiceDependency, 0, len(outgoingDeps)),
		}
		for _, dep := range outgoingDeps {
			report.OutgoingDependencies = append(report.OutgoingDependencies, dep)
		}
		sort.Slice(report.OutgoingDependencies, func(i, j int) bool {
			return report.OutgoingDependencies[i].Domain < report.OutgoingDependencies[j].Domain
		})
		serviceReports[serviceName] = report
	}

	// Convert incomingMap to a slice and sort by Domain, then Service
	incomingSlice := make([]ServiceDependency, 0, len(incomingMap))
	for _, dep := range incomingMap {
		incomingSlice = append(incomingSlice, dep)
	}
	sort.Slice(incomingSlice, func(i, j int) bool {
		if incomingSlice[i].Domain != incomingSlice[j].Domain {
			return incomingSlice[i].Domain < incomingSlice[j].Domain
		}
		return incomingSlice[i].Service < incomingSlice[j].Service
	})

	return serviceReports, incomingSlice
}

func printReport(outgoing map[string]*ServiceReport, incoming []ServiceDependency, domainsOnly bool) {
	if len(outgoing) == 0 && len(incoming) == 0 {
		fmt.Println("No services with dependencies found.")
		return
	}

	// Sort service names for consistent output
	serviceNames := make([]string, 0, len(outgoing))
	for serviceName := range outgoing {
		serviceNames = append(serviceNames, serviceName)
	}
	sort.Strings(serviceNames)

	if len(outgoing) > 0 {
		if domainsOnly {
			fmt.Println("Target-Domain,Last-Access")
		} else {
			fmt.Println("Service,Target-Domain,Last-Access")
		}

		for _, serviceName := range serviceNames {
			report := outgoing[serviceName]
			if len(report.OutgoingDependencies) > 0 {
				for _, dep := range report.OutgoingDependencies {
					if domainsOnly {
						fmt.Printf("%s,%s\n", dep.Domain, dep.LastAccess)
					} else {
						fmt.Printf("%s,%s,%s\n", report.ServiceName, dep.Domain, dep.LastAccess)
					}
				}
			}
		}
	}

	if len(incoming) > 0 {
		if len(outgoing) > 0 {
			fmt.Println()
		}
		if domainsOnly {
			fmt.Println("Source-Domain,Last-Access")
		} else {
			fmt.Println("Source-Domain,Source-Service,Last-Access")
		}
		for _, dep := range incoming {
			if domainsOnly {
				fmt.Printf("%s,%s\n", dep.Domain, dep.LastAccess)
			} else {
				fmt.Printf("%s,%s,%s\n", dep.Domain, dep.Service, dep.LastAccess)
			}
		}
	}
}
