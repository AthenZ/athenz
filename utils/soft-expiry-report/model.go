package main

type Product struct {
	InterimEdit               string      `json:"interimEdit"`
	IsSoxEnabled              string      `json:"isSoxEnabled"`
	ProductOwnerShortID       string      `json:"productOwnerShortId"`
	Name                      string      `json:"name"`
	EngineeringOwnerLastName  string      `json:"engineeringOwnerLastName"`
	ProductOwnerLastName      string      `json:"productOwnerLastName"`
	ID                        int         `json:"id"`
	Key                       int         `json:"key"`
	ModifiedDateRaw           int64       `json:"modifiedDateRaw"`
	EngineeringOwnerTitle     string      `json:"engineeringOwnerTitle"`
	ProductOwnerWorkEmail     string      `json:"productOwnerWorkEmail"`
	ProductID                 string      `json:"productId"`
	PropertyCount             int         `json:"propertyCount"`
	Comment                   string      `json:"comment"`
	FamilyDesc                string      `json:"familyDesc"`
	IsCurrent                 bool        `json:"isCurrent"`
	BusinessClassificationID  string      `json:"businessClassificationId"`
	FamilyKey                 int         `json:"familyKey"`
	FamilyID                  string      `json:"familyId"`
	ModifiedDate              string      `json:"modifiedDate"`
	VerticalFamilyDesc        string      `json:"verticalFamilyDesc"`
	EngineeringOwnerFirstName string      `json:"engineeringOwnerFirstName"`
	OwnGroup                  string      `json:"ownGroup"`
	VerticalKey               int         `json:"verticalKey"`
	EngineeringOwnerWorkEmail string      `json:"engineeringOwnerWorkEmail"`
	ProductOwnerFirstName     string      `json:"productOwnerFirstName"`
	InactivePropertyCount     string      `json:"inactivePropertyCount"`
	ApprovalDate              string      `json:"approvalDate"`
	EngineeringOwnerShortID   string      `json:"engineeringOwnerShortId"`
	LongDescription           string      `json:"longDescription"`
	ApprovedBy                string      `json:"approvedBy"`
	CurrentPropertyCount      string      `json:"currentPropertyCount"`
	CreatedDate               string      `json:"createdDate"`
	VerticalFamilyKey         int         `json:"verticalFamilyKey"`
	AthenzDomain              string      `json:"athenzDomain"`
	ModifiedBy                string      `json:"modifiedBy"`
	ApprovalDateRaw           string      `json:"approvalDateRaw"`
	ProductOwnerTitle         string      `json:"productOwnerTitle"`
	CreatedBy                 string      `json:"createdBy"`
	Status                    string      `json:"status"`
	CreatedDateRaw            int64       `json:"createdDateRaw"`
	VerticalDesc              string      `json:"verticalDesc"`
}

type Products []Product
