package main

import (
	"log"
	"test/wazuh"
)

func main() {

	log.Println("started")
	inst := wazuh.WazuhCreateInstance("https://", "10.100.50.10", ":55000/", "wazuh", "wazuh")
	log.Println(inst)
	add_Policy_To_Role, code400, code403, code429, errorCode := wazuh.AddPolicyToRole(inst, "104", "100")
	log.Println(add_Policy_To_Role, code400, code403, code429, errorCode)
}
