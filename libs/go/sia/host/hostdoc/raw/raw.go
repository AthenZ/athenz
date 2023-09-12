package raw

import "time"

// JsonDoc is used mainly for unmarshalling the raw doc
// it is used for backward compatibility to allow both service and services keys
type Doc struct {
	Provider          string    `json:"provider,omitempty"`
	Domain            string    `json:"domain"`
	Service           string    `json:"service"`
	Services          string    `json:"services,omitempty"`
	Profile           string    `json:"profile"`
	ProfileRestrictTo string    `json:"profile_restrict_to,omitempty"`
	AccountId         string    `json:"account_id,omitempty"`
	ProjectNumber     string    `json:"project_number,omitempty"`
	Uuid              string    `json:"uuid,omitempty"`
	Ip                []string  `json:"ip,omitempty"`
	Zone              string    `json:"zone,omitempty"`
	LaunchTime        time.Time `json:"launch_time,omitempty"` // stop/start an instance will update the LaunchTime
}
