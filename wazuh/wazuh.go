package wazuh

import (
	"crypto/tls"
	"log"
	"net/http"

	jsoniter "github.com/json-iterator/go"
)

func WazuhCreateInstance(protocol, addr, port, username, password string) WazuhInst {
	instance := WazuhInst{addr: protocol + addr + port, user: username, pass: password, transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	instance.client = &http.Client{Transport: instance.transport}
	instance.token = getToken(instance)
	//instance.token = ""
	return instance
}

func GetAllUsers(instance WazuhInst) (WazuhUser, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhGetMethod(instance, "/security/users?pretty=true")
	if httpCode == 200 {
		userParsed := WazuhUser{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhUser{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhUser{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhUser{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func CreateNewUser(instance WazuhInst, user string, password string) (WazuhUser, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhPostMethod(instance, "/security/users?pretty=true", `{"username":"`+user+`","password":"`+password+`"}`)
	if httpCode == 200 {
		userParsed := WazuhUser{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("CreateUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhUser{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhUser{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhUser{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func ChangeUserPass(instance WazuhInst, password string, id string) (WazuhUser, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhPutMethod(instance, "/security/users/"+id+"?pretty=true", `{"password":"`+password+`"}`)
	if httpCode == 200 {
		userParsed := WazuhUser{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhUser{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhUser{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhUser{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}
func DeleteUser(instance WazuhInst, userid string) (WazuhUser, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhDeleteMethod(instance, `/security/users?user_ids=`+userid+`&pretty=true`)
	if httpCode == 200 {
		userParsed := WazuhUser{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhUser{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhUser{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhUser{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}
func GetAllRoles(instance WazuhInst) (WazuhRole, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhGetMethod(instance, "/security/roles?pretty=true")
	if httpCode == 200 {
		userParsed := WazuhRole{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhRole{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhRole{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhRole{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func CreateNewRole(instance WazuhInst, rolename string) (WazuhRole, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhPostMethod(instance, "/security/roles?pretty=true", `{"name":"`+rolename+`"}`)
	if httpCode == 200 {
		userParsed := WazuhRole{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("CreateUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhRole{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhRole{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhRole{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func ChangeRole(instance WazuhInst, roleid string, rolename string) (WazuhRole, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhPutMethod(instance, "/security/roles/?role_id="+roleid+"&pretty=true", `{"name": "`+rolename+`"}`)
	if httpCode == 200 {
		userParsed := WazuhRole{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhRole{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhRole{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhRole{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}
func DeleteRole(instance WazuhInst, roleid string) (WazuhRole, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhDeleteMethod(instance, "/roles?role_ids="+roleid+"100&pretty=true")
	if httpCode == 200 {
		userParsed := WazuhRole{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhRole{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhRole{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhRole{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}
func GetAllRules(instance WazuhInst, ruleid string) (WazuhRule, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhGetMethod(instance, "/security/rules?rule_ids="+ruleid+"&pretty=true")
	if httpCode == 200 {
		userParsed := WazuhRule{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllrules Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhRule{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhRule{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhRule{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func CreateNewRule(instance WazuhInst, rulename string, ruledef string) (WazuhRule, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhPostMethod(instance, "/security/rules?pretty=true", `{"name": "`+rulename+`","rule": {"MATCH": {"definition":"`+ruledef+`"}}}`)
	if httpCode == 200 {
		userParsed := WazuhRule{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("CreateUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhRule{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhRule{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhRule{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func ChangeRule(instance WazuhInst, ruleid string, rulename string, ruledef string) (WazuhRule, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhPutMethod(instance, "/security/rules/"+ruleid+"102?pretty=true", `{"name": "`+rulename+`","rule": {"MATCH": {"definition":"`+ruledef+`"}}}`)
	if httpCode == 200 {
		userParsed := WazuhRule{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhRule{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhRule{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhRule{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}
func DeleteRule(instance WazuhInst, ruleid string) (WazuhRule, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhDeleteMethod(instance, "rules?rule_ids="+ruleid+"&pretty=true")
	if httpCode == 200 {
		userParsed := WazuhRule{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhRule{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhRule{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhRule{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func GetAllPolicies(instance WazuhInst) (WazuhPolicy, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhGetMethod(instance, "/security/policies?pretty=true")
	if httpCode == 200 {
		userParsed := WazuhPolicy{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllPolicies Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhPolicy{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhPolicy{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhPolicy{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func CreateNewPolicy(instance WazuhInst, policyname string) (WazuhPolicy, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhPostMethod(instance, "/security/policies?pretty=true", `{"name": "`+policyname+`","policy": {"actions": ["agent:delete"],"resources": ["agent:id:008"],"effect": "allow"}}`)
	if httpCode == 200 {
		userParsed := WazuhPolicy{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("CreateUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhPolicy{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhPolicy{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhPolicy{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func ChangePolicy(instance WazuhInst, policyid string, policyname string) (WazuhPolicy, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhPutMethod(instance, "/security/policies/"+policyid+"?pretty=true", `{"name": "`+policyname+`","policy": {"actions": ["agent:delete"],"resources": ["agent:id:008"],"effect": "allow"}}`)
	if httpCode == 200 {
		userParsed := WazuhPolicy{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhPolicy{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhPolicy{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhPolicy{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}
func DeletePolicy(instance WazuhInst, policyid string) (WazuhPolicy, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhDeleteMethod(instance, "/security/policies?policy_ids="+policyid+"&pretty=true")
	if httpCode == 200 {
		userParsed := WazuhPolicy{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhPolicy{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhPolicy{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhPolicy{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func AddPolicyToRole(instance WazuhInst, roleid string, policyid string) (WazuhAddPolicyToRole, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhPostMethod(instance, "/security/roles/"+roleid+"/policies?policy_ids="+policyid+"&pretty=true", ``)
	if httpCode == 200 {
		userParsed := WazuhAddPolicyToRole{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("CreateUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhAddPolicyToRole{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhAddPolicyToRole{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhAddPolicyToRole{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func RemovePolicyFromRole(instance WazuhInst, roleid string, policyid string) (WazuhAddPolicyToRole, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhDeleteMethod(instance, "/security/roles/"+roleid+"/policies?policy_ids="+policyid+"pretty=true")
	if httpCode == 200 {
		userParsed := WazuhAddPolicyToRole{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhAddPolicyToRole{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhAddPolicyToRole{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhAddPolicyToRole{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}
func AddRuleToRole(instance WazuhInst, roleid string, ruleid string) (WazuhAddRulesToRole, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhPostMethod(instance, "/security/roles/"+roleid+"/rules?rule_ids="+ruleid+"&pretty=true", ``)
	if httpCode == 200 {
		userParsed := WazuhAddRulesToRole{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("AddRuleToRole Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhAddRulesToRole{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhAddRulesToRole{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhAddRulesToRole{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func RemoveRuleFromRole(instance WazuhInst, roleid string, ruleid string) (WazuhAddRulesToRole, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhDeleteMethod(instance, "/security/roles/"+roleid+"/rules?rule_ids="+ruleid+"&pretty=true")
	if httpCode == 200 {
		userParsed := WazuhAddRulesToRole{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhAddRulesToRole{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhAddRulesToRole{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhAddRulesToRole{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func AddRoleToUser(instance WazuhInst, userid string, roleid string) (WazuhAddRoleToUser, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhPostMethod(instance, "/security/users/"+userid+"/roles?role_ids="+roleid+"&pretty=true", ``)
	if httpCode == 200 {
		userParsed := WazuhAddRoleToUser{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("CreateUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhAddRoleToUser{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhAddRoleToUser{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhAddRoleToUser{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func RemoveRoleFromUser(instance WazuhInst, userid string, roleid string) (WazuhAddRoleToUser, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhDeleteMethod(instance, "/security/users/"+userid+"/roles?role_ids="+roleid+"&pretty=true")
	if httpCode == 200 {
		userParsed := WazuhAddRoleToUser{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getAllUsers Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhAddRoleToUser{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhAddRoleToUser{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhAddRoleToUser{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

func GetLogs(instance WazuhInst) (WazuhLogs, Wazuh400_401_405, Wazuh403, Wazuh429, int) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonResponse, httpCode := wazuhGetMethod(instance, "/manager/logs?pretty=true")
	if httpCode == 200 {
		userParsed := WazuhLogs{}
		json.Unmarshal([]byte(jsonResponse), &userParsed)
		if userParsed.Error != 0 {
			log.Println("getLogs Returned bad error code")
			return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, userParsed.Error
		}
		return userParsed, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
	} else if httpCode == 403 {
		json403Parsed := Wazuh403{}
		json.Unmarshal([]byte(jsonResponse), &json403Parsed)
		return WazuhLogs{}, Wazuh400_401_405{}, json403Parsed, Wazuh429{}, 0
	} else if httpCode == 400 || httpCode == 401 || httpCode == 405 {
		json400Parsed := Wazuh400_401_405{}
		json.Unmarshal([]byte(jsonResponse), &json400Parsed)
		return WazuhLogs{}, json400Parsed, Wazuh403{}, Wazuh429{}, 0
	}
	return WazuhLogs{}, Wazuh400_401_405{}, Wazuh403{}, Wazuh429{}, 0
}

/*
func main() {

	//testInstance := wazuhCreateInstance() //create instance
	testInstance := wazuhCreateInstance()
	//userList, code400, code403, code429, errorCode := getAllUsers(testInstance)
	//userList, code400, code403, code429, errorCode := createNewUser(testInstance, "newapiuser", "NewAPIùser1")
	//userList, code400, code403, code429, errorCode := changeUserPass(testInstance, "newapiuser", "NewAPIùser1")
	//userList, code400, code403, code429, errorCode := deleteUser(testInstance, "927")
	//roleList, code400, code403, code429, errorCode := getAllRoles(testInstance)
	//roleList, code400, code403, code429, errorCode := createNewRole(testInstance,"NewRoleForWazuh")
	//roleList, code400, code403, code429, errorCode := changeRole(testInstance,"ModifiedRoleForWazuh")
	//roleList, code400, code403, code429, errorCode := deleteRole(testInstance, "103")
	//ruleList, code400, code403, code429, errorCode := getAllRules(testInstance, "31106")
	//ruleList, code400, code403, code429, errorCode := createNewRule(testInstance,"NewRuleForWazuh","DescriptionOfNewRule")
	//ruleList, code400, code403, code429, errorCode := changeRule(testInstance,"100","ModifiedRoleForWazuh","ModifiedDescription")
	//ruleList, code400, code403, code429, errorCode := deleteRule(testInstance, "106")
	//policyList, code400, code403, code429, errorCode := getAllPolicies(testInstance)
	//policyList, code400, code403, code429, errorCode := createNewPolicy(testInstance,"NewPolicyForWazuh")
	//policyList, code400, code403, code429, errorCode := changePolicy(testInstance,"101","ModifiedPolicyForWazuh")
	//policyList, code400, code403, code429, errorCode := deletePolicy(testInstance, "101")
	//ADD_ROLE_TO_USER_API
	//log.Println(wazuhPostMethod(instance, "/security/users/100/roles?role_ids=102&pretty=true", ``))
	//add_Policy_To_Role, code400, code403, code429, errorCode := addPolicyToRole(testInstance,"102","100")
	remove_Policy_From_Role, code400, code403, code429, errorCode := removePolicyFromRole(testInstance,"102","100")
	log.Println(remove_Policy_From_Role, code400, code403, code429, errorCode)
	//REMOVE_ROLE_FROM_USER_API
	//log.Println(wazuhDeleteMethod(instance, "/security/users/100/roles?role_ids=102&pretty=true"))
	//ADD_POLICY_TO_ROLE_API
	//log.Println(wazuhPostMethod(instance, "/security/roles/102/policies?policy_ids=100&pretty=true", ``))
	//REMOVE_POLICY_FROM_ROLE_API
	//log.Println(wazuhDeleteMethod(instance, "/security/roles/102/policies?policy_ids=100&pretty=true"))
	//ADD_RULE_TO_ROLE
	//log.Println(wazuhPostMethod(instance, "/security/roles/102/rules?rule_ids=102&pretty=true", ``))
	//REMOVE_RULE_FROM_ROLE
	//log.Println(wazuhDeleteMethod(instance, "/security/roles/102/rules?rule_ids=102&pretty=true"))
	//GET_SECURITY_CONFIG
	//log.Println(wazuhGetMethod(instance, "/security/config?pretty=true"))
	//Update_security_config
	//log.Println(wazuhPutMethod(instance, "/security/config?pretty=true", `{"auth_token_exp_timeout":989,"rbac_mode": "white"}`))
	//Restore_default_security_config
	//log.Println(wazuhDeleteMethod(instance, "/security/config?pretty=true"))??
}

// go run requests.go
*/
