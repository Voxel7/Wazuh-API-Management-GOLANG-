package wazuh

import "net/http"

type WazuhInst struct {
	addr      string
	user      string
	pass      string
	token     string
	transport *http.Transport
	client    *http.Client
}

type Wazuh400_401_405 struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

type Wazuh403 struct {
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
	Error       int    `json:"error"`
	DapiErrors  struct {
		UnknownNode struct {
			Error string `json:"error"`
		} `json:"unknown-node"`
	} `json:"dapi_errors"`
}

type Wazuh429 struct {
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
	Code        int    `json:"code"`
}

type WazuhUser struct {
	Data struct {
		AffectedItems      []interface{} `json:"affected_items"`
		TotalAffectedItems int           `json:"total_affected_items"`
		TotalFailedItems   int           `json:"total_failed_items"`
		FailedItems        []interface{} `json:"failed_items"`
	} `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}

type WazuhRole struct {
	Data struct {
		AffectedItems []struct {
			ID       int    `json:"id"`
			Name     string `json:"name"`
			Policies []int  `json:"policies"`
			Users    []int  `json:"users"`
			Rules    []int  `json:"rules"`
		} `json:"affected_items"`
		TotalAffectedItems int           `json:"total_affected_items"`
		TotalFailedItems   int           `json:"total_failed_items"`
		FailedItems        []interface{} `json:"failed_items"`
	} `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}

type WazuhRule struct {
	Data struct {
		AffectedItems []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
			Rule struct {
				Find struct {
					Username string `json:"username"`
				} `json:"FIND"`
			} `json:"rule"`
			Roles []int `json:"roles"`
		} `json:"affected_items"`
		TotalAffectedItems int           `json:"total_affected_items"`
		TotalFailedItems   int           `json:"total_failed_items"`
		FailedItems        []interface{} `json:"failed_items"`
	} `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}

type WazuhPolicy struct {
	Data struct {
		AffectedItems []struct {
			ID     int    `json:"id"`
			Name   string `json:"name"`
			Policy struct {
				Actions   []string `json:"actions"`
				Resources []string `json:"resources"`
				Effect    string   `json:"effect"`
			} `json:"policy"`
			Roles []int `json:"roles"`
		} `json:"affected_items"`
		TotalAffectedItems int           `json:"total_affected_items"`
		TotalFailedItems   int           `json:"total_failed_items"`
		FailedItems        []interface{} `json:"failed_items"`
	} `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}

type WazuhAddRoleToUser struct {
	Data struct {
		AffectedItems []struct {
			ID         int    `json:"id"`
			Username   string `json:"username"`
			AllowRunAs bool   `json:"allow_run_as"`
			Roles      []int  `json:"roles"`
		} `json:"affected_items"`
		TotalAffectedItems int           `json:"total_affected_items"`
		TotalFailedItems   int           `json:"total_failed_items"`
		FailedItems        []interface{} `json:"failed_items"`
	} `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}

type WazuhAddPolicyToRole struct {
	Data struct {
		AffectedItems []struct {
			ID       int           `json:"id"`
			Name     string        `json:"name"`
			Policies []int         `json:"policies"`
			Users    []interface{} `json:"users"`
			Rules    []interface{} `json:"rules"`
		} `json:"affected_items"`
		TotalAffectedItems int           `json:"total_affected_items"`
		TotalFailedItems   int           `json:"total_failed_items"`
		FailedItems        []interface{} `json:"failed_items"`
	} `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}

type WazuhAddRulesToRole struct {
	Data struct {
		AffectedItems []struct {
			ID       int           `json:"id"`
			Name     string        `json:"name"`
			Policies []interface{} `json:"policies"`
			Users    []interface{} `json:"users"`
			Rules    []int         `json:"rules"`
		} `json:"affected_items"`
		TotalAffectedItems int           `json:"total_affected_items"`
		TotalFailedItems   int           `json:"total_failed_items"`
		FailedItems        []interface{} `json:"failed_items"`
	} `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}

type WazuhLogs struct {
	Data struct {
		AffectedItems []struct {
			Timestamp   string `json:"timestamp"`
			Tag         string `json:"tag"`
			Level       string `json:"level"`
			Description string `json:"description"`
		} `json:"affected_items"`
		TotalAffectedItems int           `json:"total_affected_items"`
		FailedItems        []interface{} `json:"failed_items"`
		TotalFailedItems   int           `json:"total_failed_items"`
	} `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}
