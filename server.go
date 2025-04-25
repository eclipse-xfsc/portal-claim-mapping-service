package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/yalp/jsonpath"
	"go.uber.org/zap"
)

func RequestLogger(targetMux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		targetMux.ServeHTTP(w, r)

		if string(r.RequestURI) != "/isAlive" {
			Logger.Infow("",
				zap.String("method", string(r.Method)),
				zap.String("uri", string(r.RequestURI)),
				zap.Duration("duration", time.Since(start)*1000),
			)
		}
	})
}

func startServer(port *int) {
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/claims", claimsGet).Methods("GET")

	router.HandleFunc("/list/roles", listRolesGet).Methods("GET")
	router.HandleFunc("/list/roles", listRolesPost).Methods("POST")
	router.HandleFunc("/list/roles", listRolesPut).Methods("PUT")
	router.HandleFunc("/list/roles", listRolesDelete).Methods("DELETE")

	router.HandleFunc("/list/claims", listClaimsGet).Methods("GET")
	router.HandleFunc("/list/claims", listClaimsPost).Methods("POST")
	router.HandleFunc("/list/claims", listClaimsPut).Methods("PUT")
	router.HandleFunc("/list/claims", listClaimsDelete).Methods("DELETE")

	router.HandleFunc("/list/mappings", listMappingsGet).Methods("GET")
	router.HandleFunc("/list/mappings", listMappingsPost).Methods("POST")
	router.HandleFunc("/list/mappings", listMappingsPut).Methods("PUT")
	router.HandleFunc("/list/mappings", listMappingsDelete).Methods("DELETE")

	router.HandleFunc("/isAlive", isAliveGet).Methods("GET")

	portString := ":" + strconv.Itoa(*port)
	log.Fatal(http.ListenAndServe(portString, RequestLogger(router)))
}

func claimsGet(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")
	// Get query params
	noContext := false
	context := r.URL.Query().Get("context")
	if len(context) == 0 {
		noContext = true
	}

	// Auth check
	token, err := GetToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Get token's roles
	tokenPayload, _ := json.Marshal(token.Claims.(jwt.MapClaims))
	var tokenData interface{}
	err = json.Unmarshal(tokenPayload, &tokenData)
	roles, err := jsonpath.Read(tokenData, config.tokenRolesPath)
	if roles == nil {
		err := "Invalid or missing roles."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}
	var rolesArray []string
	for _, role := range roles.([]interface{}) {
		rolesArray = append(rolesArray, role.(string))
	}

	var responseBody []interface{}

	if noContext {
		// Get token's context
		tokenContext, err := jsonpath.Read(tokenData, config.tokenContextPath)
		if tokenContext == nil {
			err := "Invalid or missing context in token."
			responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
			var responseJson map[string]interface{}
			w.WriteHeader(409)
			json.Unmarshal(responseBody, &responseJson)
			json.NewEncoder(w).Encode(responseJson)

			return
		}

		// Get DB claims
		claims, err := dbListContextRolesClaims(config, tokenContext.(string), rolesArray)
		if err != nil {
			Logger.Error(err)
			w.WriteHeader(500)
			return
		}

		if len(claims) == 0 {
			contextClaims := make(map[string]interface{})
			contextClaims["context"] = tokenContext.(string)
			contextClaims["claims"] = make([]interface{}, 0)
			responseBody = append(responseBody, contextClaims)
		} else {
			for _, claim := range claims {
				/*exist := false
				for index, cont := range responseBody {
					if cont.(map[string]interface{})["context"] == claim.Context {
						exist = true

						contextPolicyURL := getContextPolicyURL(claim.Context)
						if len(contextPolicyURL) > 0 {
							claimsString := []string{claim.Claim}
							tsaClaims, err := tsaGetContextClaimsRequest(contextPolicyURL, claim.Context, claimsString, token.Raw)
							if err != nil {
								Logger.Error(err)
								w.WriteHeader(500)
								return
							}

							for _, tsaClaim := range tsaClaims["claims"].([]string) {
								if claim.Claim == tsaClaim {
									responseBody[index].(map[string]interface{})["claims"] = append(responseBody[index].(map[string]interface{})["claims"].([]interface{}), claim)
								}
							}
						} else {
							responseBody[index].(map[string]interface{})["claims"] = append(responseBody[index].(map[string]interface{})["claims"].([]interface{}), claim)
						}
					}
				}*/
				//	if exist == false {
				contextClaims := make(map[string]interface{})
				contextClaims["context"] = claim.Context
				var claims []interface{}
				contextPolicyURL := getContextPolicyURL(claim.Context)
				if len(contextPolicyURL) > 0 {
					claimsString := []string{claim.Claim}
					tsaClaims, err := tsaGetContextClaimsRequest(contextPolicyURL, claim.Context, claimsString, token.Raw)
					if err != nil {
						Logger.Error(err)
						w.WriteHeader(500)
						return
					}

					for _, tsaClaim := range tsaClaims["claims"].([]string) {
						if claim.Claim == tsaClaim {
							claims = append(claims, claim)
							contextClaims["claims"] = claims

							responseBody = append(responseBody, contextClaims)
						}
					}
				} else {
					claims = append(claims, claim)
					contextClaims["claims"] = claims

					responseBody = append(responseBody, contextClaims)
				}
				//	}
			}
		}
		// Append default claims
		if len(config.defaultClaims) > 0 {
			for index, contextClaims := range responseBody {
				for _, claimConfig := range config.defaultClaims {
					if claimConfig.Context == tokenContext.(string) || claimConfig.Context == "*" {
						hasRole := hasRole(rolesArray, claimConfig.Roles)
						if hasRole {
							currentClaims := contextClaims.(map[string]interface{})["claims"].([]interface{})
							for _, defaultClaim := range claimConfig.Claims {
								added := false
								for _, claim := range currentClaims {
									if defaultClaim == claim.(contextClaim).Claim {
										added = true
									}
								}
								if !added {
									newClaim := contextClaim{
										Id:      0,
										Claim:   defaultClaim,
										RowVer:  0,
										Context: tokenContext.(string),
									}
									currentClaims = append(currentClaims, newClaim)
									newContextClaim := make(map[string]interface{})
									newContextClaim["context"] = tokenContext.(string)
									newContextClaim["claims"] = currentClaims
									responseBody[index] = newContextClaim
								}
							}
						}
					}
				}
			}
		}
	} else {
		// Get DB claims
		claims, err := dbListContextRolesClaims(config, context, rolesArray)
		if err != nil {
			Logger.Error(err)
			w.WriteHeader(500)
			return
		}
		contextClaims := make(map[string]interface{})

		contextPolicyURL := getContextPolicyURL(context)
		if len(contextPolicyURL) > 0 {
			var claimsString []string
			for _, claim := range claims {
				claimsString = append(claimsString, claim.Claim)
			}
			tsaClaims, err := tsaGetContextClaimsRequest(contextPolicyURL, context, claimsString, token.Raw)
			if err != nil {
				Logger.Error(err)
				w.WriteHeader(500)
				return
			}

			contextClaims["context"] = context
			var finalClaims []interface{}
			for _, claim := range claims {
				for _, tsaClaim := range tsaClaims["claims"].([]string) {
					if claim.Claim == tsaClaim {
						finalClaims = append(finalClaims, claim)
					}
				}
			}
			contextClaims["claims"] = finalClaims
		} else {
			contextClaims["context"] = context
			contextClaims["claims"] = claims
		}

		appendDefaultClaims(context, config.defaultClaims, contextClaims, rolesArray)
		responseBody = append(responseBody, contextClaims)
	}

	json.NewEncoder(w).Encode(responseBody)
	return
}

func listRolesGet(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	roles, err := dbListRoles(config)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}

	json.NewEncoder(w).Encode(roles)
	return
}

func listRolesPost(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	// Auth check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	var newRoles []role
	err = json.NewDecoder(r.Body).Decode(&newRoles)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var rolesNames []string
	for _, role := range newRoles {
		rolesNames = append(rolesNames, role.Role)
	}

	err = dbInsertRoles(config, rolesNames)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(201)

	return
}

func listRolesPut(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	// Auth check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Get query params
	id := r.URL.Query().Get("id")
	if len(id) == 0 {
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	idNumber, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		Logger.Error(err)
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	// Get body params
	var payload map[string]interface{}
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	roleName, ok := payload["role"].(string)
	if !ok {
		http.Error(w, "Missing or invalid parameter \"role\"", http.StatusBadRequest)
		return
	}
	rowVersion, ok := payload["rowversion"].(float64)
	if !ok {
		http.Error(w, "Missing or invalid parameter \"rowversion\"", http.StatusBadRequest)
		return
	}

	updatedRole := role{
		Id:     idNumber,
		Role:   roleName,
		RowVer: int64(rowVersion),
	}

	err = dbUpdateRole(config, updatedRole)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}

	return
}

func listRolesDelete(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	// Auth check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Get query params
	id := r.URL.Query().Get("id")
	if len(id) == 0 {
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	idNumber, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		Logger.Error(err)
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	err = dbDeleteRole(config, idNumber)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}

	return
}

func listClaimsGet(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	claims, err := dbListClaims(config)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}

	json.NewEncoder(w).Encode(claims)
	return
}

func listClaimsPost(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	// Auth check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	var newClaims []claim
	err = json.NewDecoder(r.Body).Decode(&newClaims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var claimsNames []string
	for _, claim := range newClaims {
		claimsNames = append(claimsNames, claim.Claim)
	}

	err = dbInsertClaims(config, claimsNames)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(201)

	return
}

func listClaimsPut(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	// Auth check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Get query params
	id := r.URL.Query().Get("id")
	if len(id) == 0 {
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	idNumber, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		Logger.Error(err)
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	// Get body params
	var payload map[string]interface{}
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	claimName, ok := payload["claim"].(string)
	if !ok {
		http.Error(w, "Missing or invalid parameter \"claim\"", http.StatusBadRequest)
		return
	}
	rowVersion, ok := payload["rowversion"].(float64)
	if !ok {
		http.Error(w, "Missing or invalid parameter \"rowversion\"", http.StatusBadRequest)
		return
	}

	updatedClaim := claim{
		Id:     idNumber,
		Claim:  claimName,
		RowVer: int64(rowVersion),
	}

	err = dbUpdateClaim(config, updatedClaim)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}

	return
}

func listClaimsDelete(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	// Auth check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Get query params
	id := r.URL.Query().Get("id")
	if len(id) == 0 {
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	idNumber, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		Logger.Error(err)
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	err = dbDeleteClaim(config, idNumber)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}

	return
}

func listMappingsGet(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	mappings, err := dbListMappings(config)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}

	json.NewEncoder(w).Encode(mappings)
	return
}

func listMappingsPost(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	// Auth check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	var newMappings []mapping
	err = json.NewDecoder(r.Body).Decode(&newMappings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check claims and roles parameters
	exist := false
	claims, err := dbListClaims(config)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}
	for _, newMapping := range newMappings {
		for _, claim := range claims {
			if newMapping.Claim_Id == claim.Id {
				exist = true
			}
		}
		if !exist {
			http.Error(w, "Invalid parameter \"claim_id\"", http.StatusBadRequest)
			return
		}
		exist = false
	}
	roles, err := dbListRoles(config)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}
	for _, newMapping := range newMappings {
		for _, role := range roles {
			if newMapping.Role_Id == role.Id {
				exist = true
			}
		}
		if !exist {
			http.Error(w, "Invalid parameter \"role_id\"", http.StatusBadRequest)
			return
		}
		exist = false
	}

	err = dbInsertMappings(config, newMappings)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(201)

	return
}

func listMappingsPut(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	// Auth check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Get query params
	id := r.URL.Query().Get("id")
	if len(id) == 0 {
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	mappingId, err := uuid.Parse(id)
	if err != nil {
		Logger.Error(err)
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	// Get body params
	var payload map[string]interface{}
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name, ok := payload["name"].(string)
	if !ok {
		http.Error(w, "Missing or invalid parameter \"name\"", http.StatusBadRequest)
		return
	}
	desc, ok := payload["desc"].(string)
	if !ok {
		http.Error(w, "Missing or invalid parameter \"desc\"", http.StatusBadRequest)
		return
	}
	context, ok := payload["context"].(string)
	if !ok {
		http.Error(w, "Missing or invalid parameter \"context\"", http.StatusBadRequest)
		return
	}
	claimId, ok := payload["claim_id"].(float64)
	if !ok {
		http.Error(w, "Missing or invalid parameter \"claim_id\"", http.StatusBadRequest)
		return
	}
	roleId, ok := payload["role_id"].(float64)
	if !ok {
		http.Error(w, "Missing or invalid parameter \"role_id\"", http.StatusBadRequest)
		return
	}
	rowVersion, ok := payload["rowversion"].(float64)
	if !ok {
		http.Error(w, "Missing or invalid parameter \"rowversion\"", http.StatusBadRequest)
		return
	}

	updatedMapping := mapping{
		Id:          mappingId,
		Context:     context,
		Claim_Id:    int64(claimId),
		Role_Id:     int64(roleId),
		Name:        name,
		Description: desc,
		RowVer:      int64(rowVersion),
	}

	// Check claims and roles parameters
	exist := false
	claims, err := dbListClaims(config)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}
	for _, claim := range claims {
		if updatedMapping.Claim_Id == claim.Id {
			exist = true
		}
	}
	if !exist {
		http.Error(w, "Invalid parameter \"claim_id\"", http.StatusBadRequest)
		return
	}
	exist = false

	roles, err := dbListRoles(config)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}
	for _, role := range roles {
		if updatedMapping.Role_Id == role.Id {
			exist = true
		}
	}
	if !exist {
		http.Error(w, "Invalid parameter \"role_id\"", http.StatusBadRequest)
		return
	}

	err = dbUpdateMapping(config, updatedMapping)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}

	return
}

func listMappingsDelete(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	// Auth check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Get query params
	id := r.URL.Query().Get("id")
	if len(id) == 0 {
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	mappingId, err := uuid.Parse(id)
	if err != nil {
		Logger.Error(err)
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	err = dbDeleteMapping(config, mappingId)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(500)
		return
	}

	return
}

func isAliveGet(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	return
}
