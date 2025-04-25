package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

type ClaimConfig struct {
	Roles   []string  `json:"roles"`
	Context string    `json:"context"`
	Claims  []string  `json:"claims"`
}

type config struct {
	port int
	identityProviderOidURL string
	tokenRolesPath, tokenContextPath string
	defaultClaims []ClaimConfig
	pgHost, pgPort, pgUser, pgPassword, pgDB string
}

func getConfig() (config, error) {
	port, found := os.LookupEnv("PORT")
    if !found {
		err := fmt.Errorf("Environemnt variable \"PORT\" not found")
		return config{}, err
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return config{}, err
	}

	identityProviderOidURL, found := os.LookupEnv("IDENTITY_PROVIDER_OID_URL")
    if !found {
		err := fmt.Errorf("Environemnt variable \"IDENTITY_PROVIDER_OID_URL\" not found")
		return config{}, err
	}

	tokenRolesPath, found := os.LookupEnv("TOKEN_ROLES_PATH")
    if !found {
		err := fmt.Errorf("Environemnt variable \"TOKEN_ROLES_PATH\" not found")
		return config{}, err
	}
	tokenContextPath, found := os.LookupEnv("TOKEN_CONTEXT_PATH")
    if !found {
		err := fmt.Errorf("Environemnt variable \"TOKEN_CONTEXT_PATH\" not found")
		return config{}, err
	}

	defaultClaims, found := os.LookupEnv("DEFAULT_CLAIMS")
    if !found {
		err := fmt.Errorf("Environemnt variable \"DEFAULT_CLAIMS\" not found")
		return config{}, err
	}

	pgHost, found := os.LookupEnv("PG_HOST")
    if !found {
		err := fmt.Errorf("Environemnt variable \"PG_HOST\" not found")
		return config{}, err
	}
	pgPort, found := os.LookupEnv("PG_PORT")
    if !found {
		err := fmt.Errorf("Environemnt variable \"PG_PORT\" not found")
		return config{}, err
	}
	pgUser, found := os.LookupEnv("PG_USER")
    if !found {
		err := fmt.Errorf("Environemnt variable \"PG_USER\" not found")
		return config{}, err
	}
	pgPassword, found := os.LookupEnv("PG_PASSWORD")
    if !found {
		err := fmt.Errorf("Environemnt variable \"PG_PASSWORD\" not found")
		return config{}, err
	}
	pgDB, found := os.LookupEnv("PG_DB")
    if !found {
		err := fmt.Errorf("Environemnt variable \"PG_DB\" not found")
		return config{}, err
	}

	var claimConfigs []ClaimConfig
	err = json.Unmarshal([]byte(defaultClaims), &claimConfigs)
	if err != nil {
		err := fmt.Errorf("Environemnt variable \"DEFAULT_CLAIMS\" is invalid")
		return config{}, err
	}

	config := config{
		port: portInt,
		identityProviderOidURL: identityProviderOidURL,
		tokenRolesPath: tokenRolesPath, tokenContextPath: tokenContextPath,
		defaultClaims: claimConfigs,
		pgHost: pgHost, pgPort: pgPort, pgUser: pgUser, pgPassword: pgPassword, pgDB: pgDB,
	}
	
	return config, nil
}

func getContextPolicyURL(context string) (string) {
	url, found := os.LookupEnv("TSA_URL_" + context)
    if !found {
		url, found = os.LookupEnv("TSA_URL_default")
		if !found {
			return ""
		}
	}

	return url
}
