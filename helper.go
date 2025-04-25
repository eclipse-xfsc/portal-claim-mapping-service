package main

func hasRole(rolesArray []string, existingRoles []string) bool {
	hasRole := false
	for _, defaultRole := range existingRoles {
		for _, role := range rolesArray {
			if defaultRole == role {
				hasRole = true
			}
		}
	}
	return hasRole
}

func appendDefaultClaims(currentContext string, defaultClaims []ClaimConfig, existingClaims map[string]interface{}, rolesArray []string) {
	if len(defaultClaims) > 0 {
		for _, claimConfig := range defaultClaims {
			if claimConfig.Context == currentContext || claimConfig.Context == "*" {
				hasRole := hasRole(rolesArray, claimConfig.Roles)
				if hasRole {
					for _, defaultClaim := range claimConfig.Claims {
						added := false
						for _, claim := range existingClaims["claims"].([]contextClaim) {
							if defaultClaim == claim.Claim {
								added = true
							}
						}
						if !added {
							newClaim := contextClaim{
								Id:      0,
								Claim:   defaultClaim,
								RowVer:  0,
								Context: existingClaims["context"].(string),
							}
							existingClaims["claims"] = append(existingClaims["claims"].([]contextClaim), newClaim)
						}
					}
				}
			}
		}
	}
}
