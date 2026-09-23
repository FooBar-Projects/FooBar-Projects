package backend

import (
	"log"
	"strconv"
	"errors"
	"strings"
	"regexp"
	"bytes"
	"fmt"
	"io"
	"context"
	"crypto/rand"
	"math/big"
	"sync"
	"os"
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"
	git "github.com/go-git/go-git/v6"
	gitClient "github.com/go-git/go-git/v6/plumbing/client"
	gitHttp "github.com/go-git/go-git/v6/plumbing/transport/http"
	gitObject "github.com/go-git/go-git/v6/plumbing/object"
	"gopkg.in/yaml.v3"
	"github.com/golang-jwt/jwt/v5"
	cp "github.com/otiai10/copy"
)


type NoBody struct {}

func fetch[TRequest any, TResponse any](
		url string,
		method string,
		headers map[string]string,
		requestBody *TRequest) (*int, *TResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var bodyReader io.Reader = nil
	if requestBody != nil {
		bodyJson, err := json.Marshal(requestBody)
		if err != nil {
			fmt.Printf("Error marshaling request body to JSON: %v\n", err)
			return nil, nil, err
		}

		bodyReader = bytes.NewBuffer(bodyJson)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return nil, nil, err
	}

	for headerName := range headers {
		headerValue, _ := headers[headerName]
		req.Header.Set(headerName, headerValue)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error making request: %v\n", err)
		return nil, nil, err
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode

	var responseBody TResponse
	err = json.NewDecoder(resp.Body).Decode(&responseBody)
	if err != nil {
		fmt.Printf("Error parsing response body: %v\n", err)
		return nil, nil, err
	}

	return &statusCode, &responseBody, nil
}

func githubRestRequest[TRequest any, TResponse any](
		url string,
		method string,
		token *string,
		headers *map[string]string,
		requestBody *TRequest) (*int, *TResponse, error) {
	allHeaders := make(map[string]string)
	allHeaders["Accept"] = "application/vnd.github+json"
	allHeaders["X-GitHub-Api-Version"] = "2026-03-10"
	if token != nil {
		allHeaders["Authorization"] = fmt.Sprintf("Bearer %s", *token)
	}

	if headers != nil {
		for headerName := range (*headers) {
			headerValue, _ := (*headers)[headerName]
			allHeaders[headerName] = headerValue
		}
	}
	
	return fetch[TRequest, TResponse](url, method, allHeaders, requestBody)
}

func GenerateJWT(appId string, privateKeyPem[]byte) (*string, error) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPem)
	if err != nil {
		return nil, err
	}

	issuedAt := time.Now().Add(-1 * time.Minute)
	expirationTime := issuedAt.Add(60 * time.Minute)
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		IssuedAt: jwt.NewNumericDate(issuedAt),
		Issuer: appId,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return nil, err
	}

	return &tokenString, nil
}

type IAT struct {
	Token string
	Expiration time.Time
}

type InstallationAccessTokenProvider struct {
	iatMap map[string]IAT
	mutex sync.RWMutex
}

func CreateIAT(
		appId string,
		installationId string,
		appPrivateKeyPem []byte,
		repositoryName *string,
		permissions map[string]string) (*IAT, error) {
	jwt, err := GenerateJWT(appId, appPrivateKeyPem)
	if err != nil {
		return nil, err
	}

	type CreateIATRequest struct {
		Repositories []string `json:"repositories,omitempty"`
		Permissions map[string]string `json:"permissions,omitempty"`
	}
	type CreateIATResponse struct {
		Token string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	var createIATRequest *CreateIATRequest
	if permissions != nil || repositoryName != nil {
		var repositories []string
		if repositoryName != nil {
			repositories = []string{*repositoryName}
		}
		createIATRequest = &CreateIATRequest {
			Permissions: permissions,
			Repositories: repositories,
		}
	}
	createIATResponseStatus, createIATResponse, err :=
		githubRestRequest[CreateIATRequest, CreateIATResponse](
			fmt.Sprintf(
				"https://api.github.com/app/installations/%s/access_tokens",
				installationId,
			),
			"POST",
			jwt,
			nil,
			createIATRequest,
		)
	
	if err != nil {
		return nil, err
	}

	if *createIATResponseStatus != 201 {
		return nil, errors.New("Failed to create installation access token")
	}

	expirationTime, err := time.Parse(
		time.RFC3339,
		createIATResponse.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}

	iat := IAT {
		Token: createIATResponse.Token,
		Expiration: expirationTime.Add(-1 * time.Minute),
	}

	return &iat, nil
}

func (p *InstallationAccessTokenProvider) IAT(
		key string,
		appId string,
		installationId string,
		appPrivateKeyPem []byte,
		repositoryName *string,
		permissions map[string]string) (*string, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	now := time.Now()
	var iat IAT
	iat, exists := p.iatMap[key]
	if !exists || now.After(iat.Expiration) {
		iatPtr, err := CreateIAT(
			appId,
			installationId,
			appPrivateKeyPem,
			repositoryName,
			permissions,
		)
		if err != nil {
			return nil, err
		}
		iat = *iatPtr
		p.iatMap[key] = iat
	}

	return &iat.Token, nil
}

type Context struct {
	AssignmentCreationAppId string
	AssignmentCreationAppInstallationId string
	AssignmentCreationAppPrivateKeyPem []byte
	ClassroomsAppId string
	ClassroomsAppInstallationId string
	ClassroomsAppPrivateKeyPem []byte
	ClassroomsRepository string
	StudentAssignmentOrganization string
	iatProvider *InstallationAccessTokenProvider
	ClassroomsUsername string
	StudentPlatformGitHostname string
	AssignmentCreationUsername string
}

func (c *Context) AssignmentCreationAppIAT() (*string, error) {
	return c.iatProvider.IAT(
		"ASSIGNMENT_CREATION",
		c.AssignmentCreationAppId,
		c.AssignmentCreationAppInstallationId,
		c.AssignmentCreationAppPrivateKeyPem,
		nil,
		nil,
	)
}

func (c *Context) ClassroomsAppIAT() (*string, error) {
	return c.iatProvider.IAT(
		"CLASSROOMS",
		c.ClassroomsAppId,
		c.ClassroomsAppInstallationId,
		c.ClassroomsAppPrivateKeyPem,
		nil,
		nil,
	)
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func parseReleaseTime(
		timeString string,
		timezoneLocation string) (*time.Time, error) {
	loc, err := time.LoadLocation(timezoneLocation)
	if err != nil {
		return nil, err
	}

	// Verify time string matches expected format
	// YYYY-MM-DDThh:mm:ss
	matched, err := regexp.MatchString(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$`, timeString)
	if err != nil {
		return nil, err
	} else if !matched {
		return nil, errors.New("Time string does not match expected format")
	}

	year, err := strconv.Atoi(timeString[0:4])
	month, err := strconv.Atoi(timeString[5:7])
	day, err := strconv.Atoi(timeString[8:10])
	hour, err := strconv.Atoi(timeString[11:13])
	minute, err := strconv.Atoi(timeString[14:16])
	second, err := strconv.Atoi(timeString[17:19])

	// Arguments: year, month, day, hour, min, sec, nsec, location
	parsedTime := time.Date(year, time.Month(month), day, hour, minute, second, 0, loc)

	return &parsedTime, nil
}

func parseSectionTime(
		timeString string) (*int, *int, error) {
	// Verify time string matches expected format
	// hh:mm
	matched, err := regexp.MatchString(`^\d{2}:\d{2}$`, timeString)
	if err != nil {
		return nil, nil, err
	} else if !matched {
		return nil, nil, errors.New("Time string does not match expected format")
	}

	hour, err := strconv.Atoi(timeString[0:2])
	minute, err := strconv.Atoi(timeString[3:5])
	
	return &hour, &minute, nil
}

var weekdayNums map[string]int = map[string]int {
	"sunday": 0,
	"monday": 1,
	"tuesday": 2,
	"wednesday": 3,
	"thursday": 4,
	"friday": 5,
	"saturday": 6,
}

func acceptAssignment(
		w *http.ResponseWriter,
		r *http.Request,
		ctx Context,
		workdir string) {
	type AcceptAssignmentHTTPResult struct {
		Status string `json:"status"`
		RepositoryURL *string `json:"repositoryURL,omitempty"`
		RepositoryAccessToken *string `json:"repositoryAccessToken,omitempty"`
		RepositoryRemoteURL *string `json:"repositoryRemoteURL,omitempty"`
	}

	type acceptAssignmentClientRequestBody struct {
		UserAccessToken string `json:"user_access_token"`
		AssignmentName string `json:"assignment_name"`
		AssignmentAcceptKey string `json:"assignment_accept_key"`
	}
	var requestBody acceptAssignmentClientRequestBody
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(*w, "Malformed JSON request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	userAccessToken := requestBody.UserAccessToken
	assignmentName := requestBody.AssignmentName
	assignmentAcceptKey := requestBody.AssignmentAcceptKey

	// Get user's GitHub username
	type GetUserResponse struct {
		Login string `json:"login"`
		Id string `json:"id"`
	}
	getUserResponseStatus, getUserResponse, err :=
		githubRestRequest[NoBody, GetUserResponse](
			"https://api.github.com/user",
			"GET",
			&userAccessToken,
			nil,
			nil,
		)
	
	if err != nil {
		http.Error(*w, "Failed to get GitHub user information", http.StatusInternalServerError)
		return
	}

	if *getUserResponseStatus == 401 {
		(*w).Header().Set("Content-Type", "application/json; charset=utf-8")
		(*w).WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(*w).Encode(AcceptAssignmentHTTPResult{
			Status: "bad-auth",
		})
		return
	} else if *getUserResponseStatus != 200 {
		http.Error(*w, "Got unexpected status code when retrieving github user information", http.StatusInternalServerError)
		return
	}

	studentUsername := getUserResponse.Login
	authenticatedStudentId := getUserResponse.Id
	
	studentAssignmentRepository := fmt.Sprintf("%s-%s", assignmentName, studentUsername)

	classroomsAppIAT, err := ctx.ClassroomsAppIAT()
	if err != nil {
		http.Error(*w, "Failed to generate installation access tokens", http.StatusInternalServerError)
		return
	}
	assignmentCreationAppIAT, err := ctx.AssignmentCreationAppIAT()
	if err != nil {
		http.Error(*w, "Failed to generate installation access tokens", http.StatusInternalServerError)
		return
	}
	
	// Clone classrooms repo into workdir/classrooms-repo
	cloneResult, err := git.PlainClone(
		filepath.Join(workdir, "classrooms-repo"),
		&git.CloneOptions{
			URL: fmt.Sprintf("https://%s.git", ctx.ClassroomsRepository),
			Depth: 1,
			Progress: os.Stdout,
			ClientOptions: []gitClient.Option{
				gitClient.WithHTTPAuth(&gitHttp.BasicAuth{
					Username: ctx.ClassroomsUsername,
					Password: *classroomsAppIAT,
				}),
			},
		},
	)
	if err != nil {
		http.Error(*w, "Failed to clone classrooms repository", http.StatusInternalServerError)
		return
	}
	defer cloneResult.Close()

	// Get assignment configuration, if it exists
	type SectionOverride struct {
		Section string `yaml:"section"`
		Key *string `yaml:"key"`
		StudentRole *string `yaml:"student_role"`
		ReleaseAt *string `yaml:"release_at"`
		UnreleaseAt *string `yaml:"unrelease_at"`
		ReleaseAtSectionStart *bool `yaml:"release_at_section_start"`
		UnreleaseAtSectionEnd *bool `yaml:"unrelease_at_section_end"`
		AcceptGeneratesInvite *bool `yaml:"accept_generates_invite"`
		AcceptGeneratesRepositoryAccessToken *bool `yaml:"accept_generates_repo_access_token"`
	}
	type StudentOverride struct {
		GithubUsername string `yaml:"github_username"`
		Key *string `yaml:"key"`
		StudentRole *string `yaml:"student_role"`
		ReleaseAt *string `yaml:"release_at"`
		UnreleaseAt *string `yaml:"unrelease_at"`
		ReleaseAtSectionStart *bool `yaml:"release_at_section_start"`
		UnreleaseAtSectionEnd *bool `yaml:"unrelease_at_section_end"`
		AcceptGeneratesInvite *bool `yaml:"accept_generates_invite"`
		AcceptGeneratesRepositoryAccessToken *bool `yaml:"accept_generates_repo_access_token"`
	}
	type AssignmentConfiguration struct {
		Name *string `yaml:"name"`
		Key *string `yaml:"key"`
		StudentRole *string `yaml:"student_role"`
		ReleaseAt *string `yaml:"release_at"`
		UnreleaseAt *string `yaml:"unrelease_at"`
		ReleaseAtSectionStart *bool `yaml:"release_at_section_start"`
		UnreleaseAtSectionEnd *bool `yaml:"unrelease_at_section_end"`
		AcceptGeneratesInvite *bool `yaml:"accept_generates_invite"`
		AcceptGeneratesRepositoryAccessToken *bool `yaml:"accept_generates_repo_access_token"`
		SectionOverrides []SectionOverride `yaml:"section_overrides"`
		StudentOverrides []StudentOverride `yaml:"student_overrides"`
	}

	var assignmentConfiguration *AssignmentConfiguration = nil
	if fileExists(
			filepath.Join(
				workdir,
				"classrooms-repo/assignments/assignments.conf",
			)) {
		yamlFile, err := os.ReadFile(filepath.Join(
			workdir,
			"classrooms-repo/assignments/assignments.conf",
		))
		if err != nil {
			http.Error(*w, "Failed to read assignments configuration", http.StatusInternalServerError)
			return
		}
		var assignmentConfigurations []AssignmentConfiguration
		err = yaml.Unmarshal(yamlFile, &assignmentConfigurations)
		if err != nil {
			http.Error(*w, "Failed to parse assignments configuration", http.StatusInternalServerError)
			return
		}

		for _, conf := range assignmentConfigurations {
			if conf.Name != nil && *conf.Name == assignmentName {
				assignmentConfiguration = &conf
				break
			}
		}
	}

	// Check if assignment template exists
	assignmentTemplateExists := fileExists(
		filepath.Join(
			workdir,
			"classrooms-repo/assignments",
			assignmentName,
		),
	)

	// If assignment to be accepted doesn't exist (no template,
	// no configuration), notify client via HTTP 404
	if assignmentConfiguration == nil &&
			!assignmentTemplateExists {
		(*w).Header().Set("Content-Type", "application/json; charset=utf-8")
		(*w).WriteHeader(http.StatusNotFound)
		json.NewEncoder(*w).Encode(AcceptAssignmentHTTPResult{
			Status: "unknown-assignment",
		})
		return
	}

	// Assignment exists. Subseqeuent checks will require knowing
	// classroom timezone (timezone_loc, IANA location string). Parse
	// classroom.conf
	type SectionConfiguration struct {
		Name string `yaml:"name"`
		Weekday string `yaml:"weekday"`
		StartTime string `yaml:"start_time"`
		EndTime string `yaml:"end_time"`
	}
	type RosteredStudent struct {
		GithubUsername string `yaml:"github_username"`
		Sections []string `yaml:"sections"`
	}
	type ClassroomConfiguration struct {
		TimezoneLocation string `yaml:"timezone_loc"`
		Sections []SectionConfiguration `yaml:"sections"`
		Roster []RosteredStudent `yaml:"roster"`
		RepositoryAccessTokenPermissions map[string]string `yaml:"repo_access_token_permissions"`
	}
	classroomConfiguration := ClassroomConfiguration { // Set defaults
		TimezoneLocation: "UTC",
	}
	var studentConfiguration *RosteredStudent = nil
	if fileExists(
			filepath.Join(workdir, "classrooms-repo/classroom.conf")) {
		yamlFile, err := os.ReadFile(filepath.Join(
			workdir,
			"classrooms-repo/classroom.conf",
		))
		if err != nil {
			http.Error(*w, "Failed to read classroom configuration", http.StatusInternalServerError)
			return
		}
		err = yaml.Unmarshal(yamlFile, &classroomConfiguration)
		if err != nil {
			http.Error(*w, "Failed to parse classroom configuration", http.StatusInternalServerError)
			return
		}

		// Get student configuration if they're rostered
		if classroomConfiguration.Roster != nil {
			for _, student := range classroomConfiguration.Roster {
				if student.GithubUsername == studentUsername {
					studentConfiguration = &student
					break
				}
			}
		}
	}

	// Helpers to merge overrides into base assignment configuration
	type StrippedAssignmentConfiguration struct {
		Key *string `yaml:"key"`
		StudentRole *string `yaml:"student_role"`
		ReleaseAt *string `yaml:"release_at"`
		UnreleaseAt *string `yaml:"unrelease_at"`
		ReleaseAtSectionStart *bool `yaml:"release_at_section_start"`
		UnreleaseAtSectionEnd *bool `yaml:"unrelease_at_section_end"`
		AcceptGeneratesInvite *bool `yaml:"accept_generates_invite"`
		AcceptGeneratesRepositoryAccessToken *bool `yaml:"accept_generates_repo_access_token"`
	}
	mergeConfigurations := func(
			conf1 *StrippedAssignmentConfiguration,
			conf2 StrippedAssignmentConfiguration) {
		if conf2.Key != nil {
			conf1.Key = conf2.Key
		}
		if conf2.StudentRole != nil {
			conf1.StudentRole = conf2.StudentRole
		}
		if conf2.ReleaseAt != nil {
			conf1.ReleaseAt = conf2.ReleaseAt
		}
		if conf2.UnreleaseAt != nil {
			conf1.UnreleaseAt = conf2.UnreleaseAt
		}
		if conf2.ReleaseAtSectionStart != nil {
			conf1.ReleaseAtSectionStart = conf2.ReleaseAtSectionStart
		}
		if conf2.UnreleaseAtSectionEnd != nil {
			conf1.UnreleaseAtSectionEnd = conf2.UnreleaseAtSectionEnd
		}
		if conf2.AcceptGeneratesInvite != nil {
			conf1.AcceptGeneratesInvite = conf2.AcceptGeneratesInvite
		}
		if conf2.AcceptGeneratesRepositoryAccessToken != nil {
			conf1.AcceptGeneratesRepositoryAccessToken = conf2.AcceptGeneratesRepositoryAccessToken
		}
	}

	// Construct base stripped assignment configuration by merging
	// assignment configuration into defaults
	defaultKey := ""
	defaultRole := "push"
	defaultReleaseAt := ""
	defaultUnreleaseAt := ""
	defaultReleaseAtSectionStart := false
	defaultUnreleaseAtSectionEnd := false
	defaultAcceptGeneratesInvite := true
	defaultAcceptGeneratesRepositoryAccessToken := false
	baseStrippedAssignmentConfiguration := StrippedAssignmentConfiguration {
		Key: &defaultKey,
		StudentRole: &defaultRole,
		ReleaseAt: &defaultReleaseAt,
		UnreleaseAt: &defaultUnreleaseAt,
		ReleaseAtSectionStart: &defaultReleaseAtSectionStart,
		UnreleaseAtSectionEnd: &defaultUnreleaseAtSectionEnd,
		AcceptGeneratesInvite: &defaultAcceptGeneratesInvite,
		AcceptGeneratesRepositoryAccessToken: &defaultAcceptGeneratesRepositoryAccessToken,
	}
	if assignmentConfiguration != nil {
		mergeConfigurations(
			&baseStrippedAssignmentConfiguration,
			StrippedAssignmentConfiguration {
				Key: assignmentConfiguration.Key,
				StudentRole: assignmentConfiguration.StudentRole,
				ReleaseAt: assignmentConfiguration.ReleaseAt,
				UnreleaseAt: assignmentConfiguration.UnreleaseAt,
				ReleaseAtSectionStart:
					assignmentConfiguration.ReleaseAtSectionStart,
				UnreleaseAtSectionEnd:
					assignmentConfiguration.UnreleaseAtSectionEnd,
				AcceptGeneratesInvite:
					assignmentConfiguration.AcceptGeneratesInvite,
				AcceptGeneratesRepositoryAccessToken:
					assignmentConfiguration.AcceptGeneratesRepositoryAccessToken,
			},
		)
	}

	var relevantSectionOverrides []SectionOverride
	// Get override for each section that the student is in and
	// append them all to relevantSectionOverrides
	if studentConfiguration != nil && len(studentConfiguration.Sections) > 0 &&
			assignmentConfiguration != nil &&
			len(assignmentConfiguration.SectionOverrides) > 0 {
		for _, sectionName := range studentConfiguration.Sections {
			for _, sectionOverride :=
					range assignmentConfiguration.SectionOverrides {
				if sectionOverride.Section == sectionName {
					// Found a match. Append, then break inner loop
					relevantSectionOverrides = append(
						relevantSectionOverrides,
						sectionOverride,
					)
					break
				}
			}
		}
	}
	
	if len(relevantSectionOverrides) == 0 {
		// Student is not in any sections with overrides. Create a pseudo
		// section override with no section name and
		// no configuration (forces below logic to attempt to accept
		// the assignment under base configuration, possibly with student
		// override but no section override)
		relevantSectionOverrides = append(
			relevantSectionOverrides,
			SectionOverride {},
		)
	}

	// Construct student override
	var strippedStudentOverride StrippedAssignmentConfiguration
	if assignmentConfiguration != nil &&
			len(assignmentConfiguration.StudentOverrides) > 0 {
		for _, studentOverride :=
				range assignmentConfiguration.StudentOverrides {
			if studentOverride.GithubUsername == studentUsername {
				// Found student. Create stripped override and break loop
				strippedStudentOverride = StrippedAssignmentConfiguration {
					Key: studentOverride.Key,
					StudentRole: studentOverride.StudentRole,
					ReleaseAt: studentOverride.ReleaseAt,
					UnreleaseAt: studentOverride.UnreleaseAt,
					ReleaseAtSectionStart:
						studentOverride.ReleaseAtSectionStart,
					UnreleaseAtSectionEnd:
						studentOverride.UnreleaseAtSectionEnd,
					AcceptGeneratesInvite:
						studentOverride.AcceptGeneratesInvite,
					AcceptGeneratesRepositoryAccessToken:
						studentOverride.AcceptGeneratesRepositoryAccessToken,
				}
				break
			}
		}
	}

	// Check if assignment can be accepted under any of the section
	// overrides
	var matchingConfig *StrippedAssignmentConfiguration
	for _, relevantSectionOverride := range relevantSectionOverrides {
		// Copy baseStrippedAssignmentConfiguration
		mergedAssignmentConfiguration := baseStrippedAssignmentConfiguration

		// Merge section override into it
		mergeConfigurations(
			&mergedAssignmentConfiguration,
			StrippedAssignmentConfiguration {
				Key: relevantSectionOverride.Key,
				StudentRole: relevantSectionOverride.StudentRole,
				ReleaseAt: relevantSectionOverride.ReleaseAt,
				UnreleaseAt: relevantSectionOverride.UnreleaseAt,
				ReleaseAtSectionStart: relevantSectionOverride.ReleaseAtSectionStart,
				UnreleaseAtSectionEnd: relevantSectionOverride.UnreleaseAtSectionEnd,
				AcceptGeneratesInvite: relevantSectionOverride.AcceptGeneratesInvite,
				AcceptGeneratesRepositoryAccessToken: relevantSectionOverride.AcceptGeneratesRepositoryAccessToken,
			},
		)

		// Merge student override into it
		mergeConfigurations(
			&mergedAssignmentConfiguration,
			strippedStudentOverride,
		)
		
		// Check if input assignment key is right
		if *mergedAssignmentConfiguration.Key != "" &&
				*mergedAssignmentConfiguration.Key != assignmentAcceptKey {
			// Doesn't match.
			continue
		}
		
		// Find section configuration if it exists
		var sectionConfiguration *SectionConfiguration
		for _, section := range classroomConfiguration.Sections {
			if section.Name == relevantSectionOverride.Section {
				sectionConfiguration = &section
				break
			}
		}

		// Compute start of release window
		var releaseAt *time.Time
		if *mergedAssignmentConfiguration.ReleaseAt != "" {
			releaseAt, err = parseReleaseTime(
				*mergedAssignmentConfiguration.ReleaseAt,
				classroomConfiguration.TimezoneLocation,
			)
			
			if err != nil {
				log.Printf(
					"Failed to parse release time %s under timezone %s\n",
					*mergedAssignmentConfiguration.ReleaseAt,
					classroomConfiguration.TimezoneLocation,
				)
				continue
			}

			// If assignment is configured to release at section start, then
			// shift releaseAt forward to start of next section instance
			if *mergedAssignmentConfiguration.ReleaseAtSectionStart {
				if relevantSectionOverride.Section == "" {
					// Pseudo section (student is not in any assigned sections,
					// but assignment is configured to be released at start
					// of assigned section). Assignment cannot be accepted
					// under this configuration (or any). Continue.
					continue
				}

				if sectionConfiguration == nil {
					// Failed to find section configuration in classroom.conf,
					// so can't determine
					// start / end time of section.
					log.Printf(
						"Failed to find configuration of section %s\n",
						relevantSectionOverride.Section,
					)
					continue
				}

				releaseAtWeekdayNum := int((*releaseAt).Weekday())
				sectionWeekdayNum, exists :=
					weekdayNums[strings.ToLower(sectionConfiguration.Weekday)]
				if !exists {
					log.Printf(
						"Bad section weekday %s\n",
						sectionConfiguration.Weekday,
					)
					continue
				}

				sectionStartHour, sectionStartMinute, err := parseSectionTime(
					sectionConfiguration.StartTime,
				)
				if err != nil {
					log.Printf(
						"Failed to parse section time %s\n",
						sectionConfiguration.StartTime,
					)
					continue
				}

				if releaseAtWeekdayNum != sectionWeekdayNum {
					// Release-at weekday is different from section weekday.
					// Shift forward to next instance of section weekday,
					// then set time to section start time.
					shiftAmount :=
						(sectionWeekdayNum + 7 - releaseAtWeekdayNum) % 7
					shifted := releaseAt.AddDate(0, 0, shiftAmount)
					shifted = time.Date(
						shifted.Year(),
						shifted.Month(),
						shifted.Day(),
						*sectionStartHour,
						*sectionStartMinute,
						0,
						0,
						shifted.Location(),
					)
					releaseAt = &shifted
				} else {
					// Release-at weekday is same as section weekday.
					// Check if release-at time is before or at section
					// start time
					releaseDaySectionStart := time.Date(
						releaseAt.Year(),
						releaseAt.Month(),
						releaseAt.Day(),
						*sectionStartHour,
						*sectionStartMinute,
						0,
						0,
						releaseAt.Location(),
					)
					if (*releaseAt).After(releaseDaySectionStart) {
						// Releases later in day than section start time.
						// Shift to next week's section start time.
						shifted := releaseDaySectionStart.AddDate(0, 0, 7)
						releaseAt = &shifted
					} else {
						// Releases earlier in day than section start time.
						// Shift forward to section start time.
						releaseAt = &releaseDaySectionStart
					}
				}
			}
		}

		// Compute end of release window similarly
		var unreleaseAt *time.Time
		if *mergedAssignmentConfiguration.UnreleaseAt != "" {
			unreleaseAt, err = parseReleaseTime(
				*mergedAssignmentConfiguration.UnreleaseAt,
				classroomConfiguration.TimezoneLocation,
			)
			
			if err != nil {
				log.Printf(
					"Failed to parse unrelease time %s under timezone %s\n",
					*mergedAssignmentConfiguration.UnreleaseAt,
					classroomConfiguration.TimezoneLocation,
				)
				continue
			}

			// If assignment is configured to unrelease at section end, then
			// shift unreleaseAt forward to end of next section instance
			if *mergedAssignmentConfiguration.UnreleaseAtSectionEnd &&
					relevantSectionOverride.Section == "" {
				// Pseudo section (student is not in any assigned sections,
				// but assignment is configured to be unreleased at end
				// of assigned section). Set it to never unrelease.
				unreleaseAt = nil
			} else if *mergedAssignmentConfiguration.UnreleaseAtSectionEnd {
				// Not pseudosection. Shift unrelease forward accordingly.

				if sectionConfiguration == nil {
					// Failed to find section configuration in classroom.conf,
					// so can't determine
					// start / end time of section.
					log.Printf(
						"Failed to find configuration of section %s\n",
						relevantSectionOverride.Section,
					)
					continue
				}

				unreleaseAtWeekdayNum := int((*unreleaseAt).Weekday())
				sectionWeekdayNum, exists :=
					weekdayNums[strings.ToLower(sectionConfiguration.Weekday)]
				if !exists {
					log.Printf(
						"Bad section weekday %s\n",
						sectionConfiguration.Weekday,
					)
					continue
				}

				sectionEndHour, sectionEndMinute, err := parseSectionTime(
					sectionConfiguration.EndTime,
				)
				if err != nil {
					log.Printf(
						"Failed to parse section time %s\n",
						sectionConfiguration.EndTime,
					)
					continue
				}

				if unreleaseAtWeekdayNum != sectionWeekdayNum {
					// Unrelease-at weekday is different from section weekday.
					// Shift forward to next instance of section weekday,
					// then set time to section end time.
					shiftAmount :=
						(sectionWeekdayNum + 7 - unreleaseAtWeekdayNum) % 7
					shifted := unreleaseAt.AddDate(0, 0, shiftAmount)
					shifted = time.Date(
						shifted.Year(),
						shifted.Month(),
						shifted.Day(),
						*sectionEndHour,
						*sectionEndMinute,
						0,
						0,
						shifted.Location(),
					)
					unreleaseAt = &shifted
				} else {
					// Unrelease-at weekday is same as section weekday.
					// Check if unrelease-at time is before or at section
					// end time
					unreleaseDaySectionEnd := time.Date(
						unreleaseAt.Year(),
						unreleaseAt.Month(),
						unreleaseAt.Day(),
						*sectionEndHour,
						*sectionEndMinute,
						0,
						0,
						unreleaseAt.Location(),
					)
					if (*unreleaseAt).After(unreleaseDaySectionEnd) {
						// Unreleases later in day than section end time.
						// Shift to next week's section end time.
						shifted := unreleaseDaySectionEnd.AddDate(0, 0, 7)
						unreleaseAt = &shifted
					} else {
						// Unreleases earlier in day than section end time.
						// Shift forward to section end time.
						unreleaseAt = &unreleaseDaySectionEnd
					}
				}
			}
		}

		// Check if we're outside release window
		now := time.Now()
		if releaseAt != nil && now.Before(*releaseAt) {
			// Not released yet according to this configuration.
			continue
		}
		if unreleaseAt != nil && now.After(*unreleaseAt) {
			// Unreleased according to this configuration.
			continue
		}

		// Inside release window, and assignment accept key is good.
		// Assignment can be accepted.
		matchingConfig = &mergedAssignmentConfiguration
		break
	}

	// If unsuccessful in finding configuration that allows assignment
	// acceptance, report error and terminate.
	if matchingConfig == nil {
		(*w).Header().Set("Content-Type", "application/json; charset=utf-8")
		(*w).WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(*w).Encode(AcceptAssignmentHTTPResult{
			Status: "denied",
		})
		return
	}

	// Assignment can be accepted.

	// Check if student assignment repository already exists.
	repoFreshlyCreated := false
	getRepositoryResponseStatus, _, err :=
		githubRestRequest[NoBody, NoBody](
			fmt.Sprintf(
				"https://api.github.com/repos/%s/%s",
				ctx.StudentAssignmentOrganization,
				studentAssignmentRepository,
			),
			"GET",
			assignmentCreationAppIAT,
			nil,
			nil,
		)
	if err != nil {
		http.Error(*w, "Failed to get student assignment repository information", http.StatusInternalServerError)
		return
	}

	if *getRepositoryResponseStatus == 404 {
		// Repo doesn't exist. Create it.
		
		type CreateRepoRequest struct {
			Name string `json:"name"`
			Description string `json:"description"`
			Private bool `json:"private"`
		}
		createRepoResponseStatus, _, err :=
			githubRestRequest[CreateRepoRequest, NoBody](
				fmt.Sprintf(
					"https://api.github.com/orgs/%s/repos",
					ctx.StudentAssignmentOrganization,
				),
				"POST",
				assignmentCreationAppIAT,
				nil,
				&CreateRepoRequest {
					Name: studentAssignmentRepository,
					Description: fmt.Sprintf(
						"%s's repository for assignment %s",
						studentUsername,
						assignmentName,
					),
					Private: true,
				},
			)
		if err != nil {
			http.Error(*w, "Failed to create student assignment repository", http.StatusInternalServerError)
			return
		}
		
		if *createRepoResponseStatus == 403 {
			http.Error(*w, "Authentication failed when generating student assignment repository", http.StatusInternalServerError)
			return
		} else if *createRepoResponseStatus == 422 {
			http.Error(*w, "Got HTTP status 422 when generating assignment repository", http.StatusInternalServerError)
			return
		} else if *createRepoResponseStatus != 201 {
			http.Error(*w, fmt.Sprintf("Got HTTP status %d when generating assignment repository", createRepoResponseStatus), http.StatusInternalServerError)
			return
		}

		repoFreshlyCreated = true

		// If assignment template exists, then create local student
		// assignment clone and push contents to remote repo
		if assignmentTemplateExists {
			// Clone remote repo
			cloneResult, err := git.PlainClone(
				filepath.Join(workdir, studentAssignmentRepository),
				&git.CloneOptions{
					URL: fmt.Sprintf(
						"https://%s/%s/%s.git",
						ctx.StudentPlatformGitHostname,
						ctx.StudentAssignmentOrganization,
						studentAssignmentRepository,
					),
					Progress: os.Stdout,
					ClientOptions: []gitClient.Option{
						gitClient.WithHTTPAuth(&gitHttp.BasicAuth{
							Username: ctx.AssignmentCreationUsername,
							Password: *assignmentCreationAppIAT,
						}),
					},
				},
			)
			if err != nil {
				http.Error(*w, "Failed to clone student assignment repository", http.StatusInternalServerError)
				return
			}
			defer cloneResult.Close()

			// Copy template files
			err = cp.Copy(
				filepath.Join(
					workdir,
					"classrooms-repo/assignments",
					assignmentName,
				),
				filepath.Join(workdir, studentAssignmentRepository),
			)
			if err != nil {
				http.Error(*w, "Failed to copy assignment template into local student repository", http.StatusInternalServerError)
				return
			}
		
			// Stage all files, commit, and push
			repository, err := git.PlainOpen(filepath.Join(workdir, studentAssignmentRepository))
			if err != nil {
				http.Error(*w, "Failed to open local student assignment Git repository", http.StatusInternalServerError)
				return
			}
			defer repository.Close()

			worktree, err := repository.Worktree()
			if err != nil {
				http.Error(*w, "Failed to open local student assignment Git repository", http.StatusInternalServerError)
				return
			}

			_, err = worktree.Add(".")
			if err != nil {
				http.Error(*w, "Failed to stage copied template files", http.StatusInternalServerError)
				return
			}

			_, err = worktree.Commit("Classroom Robot: Instantiate assignment", &git.CommitOptions{
				Author: &gitObject.Signature{
					Name:  "Classroom Robot",
					Email: "<>",
					When:  time.Now(),
				},
			})
			if err != nil {
				http.Error(*w, "Failed to create commit with assignment template contents", http.StatusInternalServerError)
				return
			}

			err = repository.Push(&git.PushOptions{})
			if err != nil {
				http.Error(*w, "Failed to push assignment template contents", http.StatusInternalServerError)
				return
			}
		}
	} else if *getRepositoryResponseStatus != 200 {
		http.Error(*w, fmt.Sprintf("Got HTTP status %d when retrieving student assignment repository", getRepositoryResponseStatus), http.StatusInternalServerError)
		return
	}

	// Determine what sort of access student needs (invite, repo access token,
	// or both)
	studentNeedsInvite := false
	if *matchingConfig.AcceptGeneratesInvite {
		// Check if student is already collaborator
		getCollaboratorResponseStatus, _, err :=
			githubRestRequest[NoBody, NoBody](
				fmt.Sprintf(
					"https://api.github.com/repos/%s/%s/collaborators/%s",
					ctx.StudentAssignmentOrganization,
					studentAssignmentRepository,
					studentUsername,
				),
				"GET",
				&userAccessToken,
				nil,
				nil,
			)
		
		if err != nil {
			http.Error(*w, "Failed to get collaborator status", http.StatusInternalServerError)
			return
		}

		if *getCollaboratorResponseStatus == 404 {
			// User is not a collaborator. Record that we may need to add them
			studentNeedsInvite = true
		} else if *getCollaboratorResponseStatus != 204 {
			http.Error(*w, fmt.Sprintf("Got HTTP status %d when retrieving collaborator status", getCollaboratorResponseStatus), http.StatusInternalServerError)
			return
		}
	}

	// If student needs any form of assignment access, before we can grant
	// it to them, we first have to check if this repo was previously
	// created and registered under a different student's ID. Get
	// STUDENT_ID repository variable, or create it if it doesn't exist
	if studentNeedsInvite || *matchingConfig.AcceptGeneratesRepositoryAccessToken {
		var studentId string
		
		// If repo wasn't just freshly created, check if it already
		// has STUDENT_ID variable
		if !repoFreshlyCreated {
			type GetRepoVariableResponse struct {
				Value string `json:"value"`
			}
			getRepoVariableResponseStatus, getRepoVariableResponse, err :=
				githubRestRequest[NoBody, GetRepoVariableResponse](
					fmt.Sprintf(
						"https://api.github.com/repos/%s/%s/actions/variables/STUDENT_ID",
						ctx.StudentAssignmentOrganization,
						studentAssignmentRepository,
					),
					"GET",
					assignmentCreationAppIAT,
					nil,
					nil,
				)
			
			if err != nil {
				http.Error(*w, "Failed to get STUDENT_ID repository variable", http.StatusInternalServerError)
				return
			}

			if *getRepoVariableResponseStatus == 200 {
				// STUDENT_ID variable already exists. Store it.
				studentId = getRepoVariableResponse.Value
			}
		}
		
		// If STUDENT_ID doesn't already exist, create it
		if studentId != "" {
			studentId = authenticatedStudentId
			
			type CreateRepoVariableRequest struct {
				Name string `json:"name"`
				Value string `json:"value"`
			}
			createRepoVariableResponseStatus, _, err :=
				githubRestRequest[CreateRepoVariableRequest, NoBody](
					fmt.Sprintf(
						"https://api.github.com/repos/%s/%s/actions/variables",
						ctx.StudentAssignmentOrganization,
						studentAssignmentRepository,
					),
					"POST",
					assignmentCreationAppIAT,
					nil,
					&CreateRepoVariableRequest {
						Name: "STUDENT_ID",
						Value: authenticatedStudentId,
					},
				)
			
			if err != nil {
				http.Error(*w, "Failed to create STUDENT_ID repository variable", http.StatusInternalServerError)
				return
			}

			if *createRepoVariableResponseStatus != 201 {
				http.Error(*w, fmt.Sprintf("Got HTTP status %s when creating STUDENT_ID repository variable", createRepoVariableResponseStatus), http.StatusInternalServerError)
				return
			}
		}

		// Verify that student ID matches authenticated student ID
		if studentId != authenticatedStudentId {
			// It doesn't match. Should only happen if students' GitHub
			// usernames change, so two students have the same username
			// throughout the duration of a classroom's use. This repo was
			// previously registered to a different student with this
			// username. (Or someone messed with STUDENT_ID).
			// Requires instructor to intervene and rename the old
			// duplciate repository to something else.
			(*w).Header().Set("Content-Type", "application/json; charset=utf-8")
			(*w).WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(*w).Encode(AcceptAssignmentHTTPResult{
				Status: "duplicate-username",
			})
			return
		}
	}

	// If we made it this far, all checks have passed. Student can be
	// granted access to repo if necessary.
	if studentNeedsInvite {
		type AddCollaboratorRequest struct {
			Permission string `json:"permission"`
		}
		addCollaboratorResponseStatus, _, err :=
			githubRestRequest[AddCollaboratorRequest, NoBody](
				fmt.Sprintf(
					"https://api.github.com/repos/%s/%s/collaborators/%s",
					ctx.StudentAssignmentOrganization,
					studentAssignmentRepository,
					studentUsername,
				),
				"PUT",
				assignmentCreationAppIAT,
				nil,
				&AddCollaboratorRequest {
					Permission: *matchingConfig.StudentRole,
				},
			)
		
		if err != nil {
			http.Error(*w, "Failed to add student as collaborator", http.StatusInternalServerError)
			return
		}

		if *addCollaboratorResponseStatus != 204 && *addCollaboratorResponseStatus != 201 {
			// 204 means student was added as collaborator, no invite needed.
			// 201 means an invite was sent. Anything else is an error.
			http.Error(*w, fmt.Sprintf("Got HTTP status %d when adding student as collaborator", addCollaboratorResponseStatus), http.StatusInternalServerError)
			return
		}
	}
	
	successResult := AcceptAssignmentHTTPResult {
		Status: "success",
	}
	
	if *matchingConfig.AcceptGeneratesInvite {
		studentRepositoryURL := fmt.Sprintf(
			"https://%s/%s/%s",
			ctx.StudentPlatformGitHostname,
			ctx.StudentAssignmentOrganization,
			studentAssignmentRepository,
		)
		successResult.RepositoryURL = &studentRepositoryURL
	}

	if *matchingConfig.AcceptGeneratesRepositoryAccessToken {
		repositoryIAT, err := CreateIAT(
			ctx.AssignmentCreationAppId,
			ctx.AssignmentCreationAppInstallationId,
			ctx.AssignmentCreationAppPrivateKeyPem,
			&studentAssignmentRepository,
			classroomConfiguration.RepositoryAccessTokenPermissions,
		)
		if err != nil {
			http.Error(*w, "Failed to create repository access token", http.StatusInternalServerError)
			return
		}

		successResult.RepositoryAccessToken = &repositoryIAT.Token
		repositoryRemoteURL := fmt.Sprintf(
			"https://%s:%s@%s/%s/%s.git",
			ctx.AssignmentCreationUsername,
			repositoryIAT.Token,
			ctx.StudentPlatformGitHostname,
			ctx.StudentAssignmentOrganization,
			studentAssignmentRepository,
		)
		successResult.RepositoryRemoteURL = &repositoryRemoteURL
	}

	(*w).Header().Set("Content-Type", "application/json; charset=utf-8")
	(*w).WriteHeader(http.StatusOK)
	json.NewEncoder(*w).Encode(successResult)
}


var globalIATProvider InstallationAccessTokenProvider

func CreateContext() Context {
	classroomsUsername, exists := os.LookupEnv("CLASSROOMS_USERNAME")
	if !exists {
		classroomsUsername = "x-access-token"
	}

	assignmentCreationUsername, exists := os.LookupEnv("ASSIGNMENT_CREATION_USERNAME")
	if !exists {
		assignmentCreationUsername = "x-access-token"
	}

	studentPlatformGitHostname, exists := os.LookupEnv("STUDENT_PLATFORM_GIT_HOSTNAME")
	if !exists {
		studentPlatformGitHostname = "github.com"
	}

	return Context {
		AssignmentCreationAppId: os.Getenv("ASSIGNMENT_CREATION_APP_ID"),
		AssignmentCreationAppInstallationId:
			os.Getenv("ASSIGNMENT_CREATION_APP_INSTALLATION_ID"),
		AssignmentCreationAppPrivateKeyPem:
			[]byte(os.Getenv("ASSIGNMENT_CREATION_APP_PRIVATE_KEY")),
		ClassroomsAppId: os.Getenv("CLASSROOMS_APP_ID"),
		ClassroomsAppInstallationId:
			os.Getenv("CLASSROOMS_APP_INSTALLATION_ID"),
		ClassroomsAppPrivateKeyPem: []byte(os.Getenv("CLASSROOMS_APP_PRIVATE_KEY")),
		ClassroomsRepository: os.Getenv("CLASSROOMS_REPO"),
		StudentAssignmentOrganization:
			os.Getenv("STUDENT_ASSIGNMENT_ORGANIZATION"),
		ClassroomsUsername: classroomsUsername,
		AssignmentCreationUsername: assignmentCreationUsername,
		StudentPlatformGitHostname: studentPlatformGitHostname,
		iatProvider: &globalIATProvider,
	}
}

var ctx Context = CreateContext()

func randomDirname(length int) (*string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return nil, err
		}
		result[i] = charset[num.Int64()]
	}
	res := string(result)
	return &res, nil
}

func CORS(w http.ResponseWriter, r *http.Request, methods string, headers string) {
	origin := r.Header.Get("Origin")
	_, _, found := strings.Cut(origin, "https://")
	if !found {
		return // Only allow CORS on https
	}
	
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", methods)
	w.Header().Set("Access-Control-Allow-Headers", headers)
}

func CORSPreflightTerminator(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
}

func Backend(w http.ResponseWriter, r *http.Request) {
	// Create directory for git operations
	dirname, err := randomDirname(32)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	dirpath := fmt.Sprintf("/tmp/%s", *dirname)
	err = os.Mkdir(dirpath, 0755)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(dirpath)

	if r.Method != http.MethodPost && r.Method != http.MethodOptions {
		http.Error(w, "Invalid request method", http.StatusBadRequest)
		return
	}

	CORS(w, r, "POST, OPTIONS", "Accept, Content-Type, Content-Length")
	
	if r.Method == http.MethodOptions {
		CORSPreflightTerminator(w, r)
	} else { // POST
		acceptAssignment(&w, r, ctx, dirpath)
	}
}

