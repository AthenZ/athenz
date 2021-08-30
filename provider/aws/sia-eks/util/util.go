package util

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"strings"
)

func GetMetaDetailsFromCreds() (string, string, string, string, error) {
	stsSession, err := session.NewSession()
	if err != nil {
		return "", "", "", "", fmt.Errorf("unable to create new session: %v", err)
	}
	region := *stsSession.Config.Region
	stsService := sts.New(stsSession)
	input := &sts.GetCallerIdentityInput{}

	result, err := stsService.GetCallerIdentity(input)
	if err != nil {
		return "", "", "", region, err
	}
	roleArn := *result.Arn
	//arn:aws:sts::123456789012:assumed-role/athenz.zts-service/i-0662a0226f2d9dc2b
	if !strings.HasPrefix(roleArn, "arn:aws:sts:") {
		return "", "", "", region, fmt.Errorf("unable to parse role arn (eks prefix error): %s", roleArn)
	}
	arn := strings.Split(roleArn, ":")
	// make sure we have correct number of components
	if len(arn) < 6 {
		return "", "", "", region, fmt.Errorf("unable to parse role arn (number of components): %s", roleArn)
	}
	// our role part as 3 components separated by /
	roleComps := strings.Split(arn[5], "/")
	if len(roleComps) != 3 {
		return "", "", "", region, fmt.Errorf("unable to parse role arn (role components): %s", roleArn)
	}
	// the first component must be assumed-role
	if roleComps[0] != "assumed-role" {
		return "", "", "", region, fmt.Errorf("unable to parse role arn (assumed-role prefix): %s", roleArn)
	}
	// second component is our athenz service name with -service suffix
	if !strings.HasSuffix(roleComps[1], "-service") {
		return "", "", "", region, fmt.Errorf("service name does not have -service suffix: %s", roleArn)
	}
	roleName := roleComps[1][0 : len(roleComps[1])-8]
	idx := strings.LastIndex(roleName, ".")
	if idx < 0 {
		return "", "", "", region, fmt.Errorf("cannot determine domain/service from arn: %s", roleArn)
	}
	domain := roleName[:idx]
	service := roleName[idx+1:]
	account := arn[4]
	return account, domain, service, region, nil
}
