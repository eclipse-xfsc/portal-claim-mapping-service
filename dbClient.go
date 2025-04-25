package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type claim struct {
	Id int64 `gorm:"column:Id;primaryKey"`
	Claim string `gorm:"column:Claim"`
	RowVer int64 `gorm:"column:RowVer;not null"`
}

type role struct {
	Id int64 `gorm:"column:Id;primaryKey"`
	Role string `gorm:"column:Role"`
	RowVer int64 `gorm:"column:RowVer;not null"`
}

type contextClaim struct {
	Id int64
	Claim string
	RowVer int64
	Context string
}

type mapping struct {
	Id uuid.UUID `gorm:"column:Id;type:uuid;primaryKey"`
	Context string `gorm:"column:Context;type:character varying(50);not null"`
	Claim_Id int64 `gorm:"column:Claim_Id;type: bigint REFERENCES \"Claims\"(\"Id\")"`
	Role_Id int64 `gorm:"column:Role_Id;type: bigint REFERENCES \"Roles\"(\"Id\")"`
	Name string `gorm:"column:Name;type:character varying(120);not null"`
	Description string `gorm:"column:Description;type:character varying(120);not null"`
	RowVer int64 `gorm:"column:RowVer;not null"`
}


func dbUrl(config config) (url string) {
	dbUrl := "postgres://" + config.pgUser + ":" + config.pgPassword + "@" + config.pgHost + ":" + config.pgPort + "/" + config.pgDB
	return dbUrl
}

func autoMigrate(config config) (){
	dsn := "host=" + config.pgHost + " user=" + config.pgUser + " password=" + config.pgPassword + " dbname=" + config.pgDB + " port=" + config.pgPort
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{DisableForeignKeyConstraintWhenMigrating: true})
	if err != nil {
		Logger.Error(err)
	}
	database, err := db.DB()
	defer database.Close()

	db.Table("Claims").AutoMigrate(&claim{})
	db.Table("Roles").AutoMigrate(&role{})
	db.Table("Mapping").AutoMigrate(&mapping{})
}

// Claims

func dbListClaims(config config) ([]claim, error) {
	dbUrl := dbUrl(config)
	claimsArray := []claim{}
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return claimsArray, err
	}
	defer conn.Close(context.Background())

	rows, err := conn.Query(context.Background(), "SELECT * FROM public.\"Claims\"")
	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return claimsArray, err
	}

	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			err := fmt.Errorf("Error while iterating dataset")
			return claimsArray, err
		}

		claim := claim{
			Id: values[0].(int64),
			Claim: values[1].(string),
			RowVer: values[2].(int64),
		}
		claimsArray = append(claimsArray, claim)
	}

	return claimsArray, nil
}

func dbInsertClaims(config config, newClaims []string) (error) {
	dbUrl := dbUrl(config)
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return err
	}
	defer conn.Close(context.Background())

	valuesString := ""
	for i, claim := range newClaims {
		if i == 0 {
			valuesString += "('" + claim + "', 1)"
		} else {
			valuesString += ", ('" + claim + "', 1)"
		}
	}

	_, err = conn.Query(context.Background(), "INSERT INTO public.\"Claims\" (\"Claim\", \"RowVer\") VALUES " + valuesString)

	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return err
	}

	return nil
}

func dbUpdateClaim(config config, updatedClaim claim) (error) {
	dbUrl := dbUrl(config)
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return err
	}
	defer conn.Close(context.Background())

	idString := strconv.FormatInt(updatedClaim.Id, 10)
	rowVerString := strconv.FormatInt(updatedClaim.RowVer, 10)
	newRowVerString := strconv.FormatInt(updatedClaim.RowVer + 1, 10)

	_, err = conn.Query(context.Background(), "UPDATE public.\"Claims\" SET \"Claim\"='" + updatedClaim.Claim + "', \"RowVer\"=" + newRowVerString + " WHERE \"Id\"=" + idString + " AND \"RowVer\"=" + rowVerString)
	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return err
	}

	return nil
}

func dbDeleteClaim(config config, id int64) (error) {
	dbUrl := dbUrl(config)
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return err
	}
	defer conn.Close(context.Background())

	idString := strconv.FormatInt(id, 10)

	_, err = conn.Query(context.Background(), "DELETE FROM public.\"Claims\" WHERE \"Id\"=" + idString)
	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return err
	}

	return nil
}


// Roles

func dbListRoles(config config) ([]role, error) {
	dbUrl := dbUrl(config)
	rolesArray := []role{}
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return rolesArray, err
	}
	defer conn.Close(context.Background())

	rows, err := conn.Query(context.Background(), "SELECT * FROM public.\"Roles\"")
	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return rolesArray, err
	}

	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			err := fmt.Errorf("Error while iterating dataset")
			return rolesArray, err
		}

		role := role{
			Id: values[0].(int64),
			Role: values[1].(string),
			RowVer: values[2].(int64),
		}
		rolesArray = append(rolesArray, role)
	}

	return rolesArray, nil
}

func dbListContextRoles(config config, contextId string) ([]role, error) {
	dbUrl := dbUrl(config)
	rolesArray := []role{}
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return rolesArray, err
	}
	defer conn.Close(context.Background())

	rows, err := conn.Query(context.Background(), "SELECT * FROM public.\"Roles\" where \"Id\" in (SELECT \"Role_Id\" FROM public.\"Mapping\" where \"Context\"='" + contextId + "')")
	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return rolesArray, err
	}

	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			err := fmt.Errorf("Error while iterating dataset")
			return rolesArray, err
		}

		role := role{
			Id: values[0].(int64),
			Role: values[1].(string),
			RowVer: values[2].(int64),
		}
		rolesArray = append(rolesArray, role)
	}

	return rolesArray, nil
}

func dbInsertRoles(config config, newRoles []string) (error) {
	dbUrl := dbUrl(config)
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return err
	}
	defer conn.Close(context.Background())

	valuesString := ""
	for i, role := range newRoles {
		if i == 0 {
			valuesString += "('" + role + "', 1)"
		} else {
			valuesString += ", ('" + role + "', 1)"
		}
	}

	_, err = conn.Query(context.Background(), "INSERT INTO public.\"Roles\" (\"Role\", \"RowVer\") VALUES " + valuesString)

	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return err
	}

	return nil
}

func dbUpdateRole(config config, updatedRole role) (error) {
	dbUrl := dbUrl(config)
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return err
	}
	defer conn.Close(context.Background())

	idString := strconv.FormatInt(updatedRole.Id, 10)
	rowVerString := strconv.FormatInt(updatedRole.RowVer, 10)
	newRowVerString := strconv.FormatInt(updatedRole.RowVer + 1, 10)

	_, err = conn.Query(context.Background(), "UPDATE public.\"Roles\" SET \"Role\"='" + updatedRole.Role + "', \"RowVer\"=" + newRowVerString + " WHERE \"Id\"=" + idString + " AND \"RowVer\"=" + rowVerString)
	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return err
	}

	return nil
}

func dbDeleteRole(config config, id int64) (error) {
	dbUrl := dbUrl(config)
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return err
	}
	defer conn.Close(context.Background())

	idString := strconv.FormatInt(id, 10)

	_, err = conn.Query(context.Background(), "DELETE FROM public.\"Roles\" WHERE \"Id\"=" + idString)
	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return err
	}

	return nil
}

func dbListRolesClaims(config config, roles []string) ([]contextClaim, error) {
	dbUrl := dbUrl(config)
	contextClaimsArray := []contextClaim{}
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return contextClaimsArray, err
	}
	defer conn.Close(context.Background())

	rolesString := ""
	for i, role := range roles {
		if i == 0 {
			rolesString += "'" + role + "'"
		} else {
			rolesString += ", '" + role + "'"
		}
	}

	rows, err := conn.Query(context.Background(), "SELECT public.\"Claims\".\"Id\", public.\"Claims\".\"Claim\", public.\"Claims\".\"RowVer\", public.\"Mapping\".\"Context\" FROM public.\"Claims\" INNER JOIN public.\"Mapping\" ON public.\"Claims\".\"Id\" = public.\"Mapping\".\"Claim_Id\" where public.\"Mapping\".\"Id\" in (SELECT \"Id\" FROM public.\"Mapping\" where \"Role_Id\" in (SELECT \"Id\" FROM public.\"Roles\" where \"Role\" in (" + rolesString + ")))")
	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return contextClaimsArray, err
	}

	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			err := fmt.Errorf("Error while iterating dataset")
			return contextClaimsArray, err
		}

		contextClaim := contextClaim{
			Id: values[0].(int64),
			Claim: values[1].(string),
			RowVer: values[2].(int64),
			Context: values[3].(string),
		}
		contextClaimsArray = append(contextClaimsArray, contextClaim)
	}

	return contextClaimsArray, nil
}

func dbListContextRolesClaims(config config, contextId string, roles []string) ([]contextClaim, error) {
	dbUrl := dbUrl(config)
	contextClaimsArray := []contextClaim{}
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return contextClaimsArray, err
	}
	defer conn.Close(context.Background())

	rolesString := ""
	for i, role := range roles {
		if i == 0 {
			rolesString += "'" + role + "'"
		} else {
			rolesString += ", '" + role + "'"
		}
	}

	rows, err := conn.Query(context.Background(), "SELECT public.\"Claims\".\"Id\", public.\"Claims\".\"Claim\", public.\"Claims\".\"RowVer\", public.\"Mapping\".\"Context\" FROM public.\"Claims\" INNER JOIN public.\"Mapping\" ON public.\"Claims\".\"Id\" = public.\"Mapping\".\"Claim_Id\" where public.\"Claims\".\"Id\" in (SELECT \"Claim_Id\" FROM public.\"Mapping\" where public.\"Mapping\".\"Context\"='" + contextId + "') AND public.\"Mapping\".\"Id\" in (SELECT \"Id\" FROM public.\"Mapping\" where \"Role_Id\" in (SELECT \"Id\" FROM public.\"Roles\" where \"Role\" in (" + rolesString + ")) AND \"Context\"='" + contextId + "')")
	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return contextClaimsArray, err
	}

	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			err := fmt.Errorf("Error while iterating dataset")
			return contextClaimsArray, err
		}

		contextClaim := contextClaim{
			Id: values[0].(int64),
			Claim: values[1].(string),
			RowVer: values[2].(int64),
			Context: values[3].(string),
		}
		contextClaimsArray = append(contextClaimsArray, contextClaim)
	}

	return contextClaimsArray, nil
}


// Mappings

func dbListMappings(config config) ([]mapping, error) {
	dbUrl := dbUrl(config)
	mappingsArray := []mapping{}
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return mappingsArray, err
	}
	defer conn.Close(context.Background())

	rows, err := conn.Query(context.Background(), "SELECT * FROM public.\"Mapping\"")
	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return mappingsArray, err
	}

	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			err := fmt.Errorf("Error while iterating dataset")
			return mappingsArray, err
		}

		ints := values[0].([16]uint8)
		bytes := []byte(ints[:])		
		id, _ := uuid.FromBytes(bytes)
		
		mapping := mapping{
			Id: id,
			Context: values[1].(string),
			Claim_Id: values[2].(int64),
			Role_Id: values[3].(int64),
			Name: values[4].(string),
			Description: values[5].(string),
			RowVer: values[6].(int64),
		}
		mappingsArray = append(mappingsArray, mapping)
	}

	return mappingsArray, nil
}

func dbInsertMappings(config config, newMappings []mapping) (error) {
	dbUrl := dbUrl(config)
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return err
	}
	defer conn.Close(context.Background())

	valuesString := ""
	for i, mapping := range newMappings {
		claimIdString := strconv.FormatInt(mapping.Claim_Id, 10)
		roleIdString := strconv.FormatInt(mapping.Role_Id, 10)
		if i == 0 {
			valuesString += "('" + mapping.Id.String() + "', '" + mapping.Context + "'," + claimIdString + "," + roleIdString + ",'" + mapping.Name + "','" + mapping.Description + "', 1)"
		} else {
			valuesString += ", ('" + mapping.Context + "'," + claimIdString + "," + roleIdString + ",'" + mapping.Name + "','" + mapping.Description + "', 1)"
		}
	}

	_, err = conn.Query(context.Background(), "INSERT INTO public.\"Mapping\" (\"Id\",\"Context\", \"Claim_Id\", \"Role_Id\", \"Name\", \"Description\", \"RowVer\") VALUES " + valuesString)

	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return err
	}

	return nil
}

func dbUpdateMapping(config config, updatedMapping mapping) (error) {
	dbUrl := dbUrl(config)
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return err
	}
	defer conn.Close(context.Background())

	idString := updatedMapping.Id.String()
	claimIdString := strconv.FormatInt(updatedMapping.Claim_Id, 10)
	roleIdString := strconv.FormatInt(updatedMapping.Role_Id, 10)
	rowVerString := strconv.FormatInt(updatedMapping.RowVer, 10)
	newRowVerString := strconv.FormatInt(updatedMapping.RowVer + 1, 10)

	_, err = conn.Query(context.Background(), "UPDATE public.\"Mapping\" SET \"Name\"='" + updatedMapping.Name + "', \"Description\"='" + updatedMapping.Description + "', \"Context\"='" + updatedMapping.Context + "', \"Claim_Id\"=" + claimIdString + ", \"Role_Id\"=" + roleIdString + ", \"RowVer\"=" + newRowVerString + " WHERE \"Id\"='" + idString + "' AND \"RowVer\"=" + rowVerString)
	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return err
	}

	return nil
}

func dbDeleteMapping(config config, id uuid.UUID) (error) {
	dbUrl := dbUrl(config)
	conn, err := pgx.Connect(context.Background(), dbUrl)
	if err != nil {
		err := fmt.Errorf("Unable to connect to database: %v\n", err)
		return err
	}
	defer conn.Close(context.Background())

	_, err = conn.Query(context.Background(), "DELETE FROM public.\"Mapping\" WHERE \"Id\"='" + id.String() + "'")
	if err != nil {
		err := fmt.Errorf("Error while executing query")
		return err
	}

	return nil
}