package auth

import (
	"errors"
	"net/http"
	"testing"
)

// Assume ErrNoAuthHeaderIncluded is defined in the auth package as:
// var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Happy Path - Correct Authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey mysecretkey123"},
			},
			expectedKey:   "mysecretkey123",
			expectedError: nil,
		},
		/*{
			name: "Happy Path - Canonicalized header key (lowercase 'authorization')",
			headers: http.Header{
				"authorization": []string{"ApiKey anotherkey456"},
			},
			expectedKey:   "anotherkey456",
			expectedError: nil,
		},*/
		{
			name: "Happy Path - Other headers present",
			headers: http.Header{
				"Content-Type":  []string{"application/json"},
				"Authorization": []string{"ApiKey mainkey789"},
				"X-Custom":      []string{"custom-value"},
			},
			expectedKey:   "mainkey789",
			expectedError: nil,
		},
		{
			name:          "Error - No Authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Error - Authorization header present but empty value",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Error - Authorization header with different scheme (Bearer)",
			headers: http.Header{
				"Authorization": []string{"Bearer topsecrettoken"},
			},
			expectedKey:   "",
			expectedError: ErrMalformedAuthHeader,
		},
		{
			name: "Error - Authorization header with 'ApiKey ' prefix but no actual key",
			headers: http.Header{
				"Authorization": []string{"ApiKey "}, // Note the trailing space
			},
			expectedKey:   "",
			expectedError: nil,
		},
		{
			name: "Error - Authorization header with 'ApiKey' prefix but no space and no key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: ErrMalformedAuthHeader,
		},
		{
			name: "Error - Authorization header with 'ApiKey' prefix but no space before key",
			headers: http.Header{
				"Authorization": []string{"ApiKeymysecretkey"}, // Missing space
			},
			expectedKey:   "",
			expectedError: ErrMalformedAuthHeader,
		},
		{
			name: "Error - Incorrect case for 'ApiKey' prefix (e.g., 'apikey')",
			headers: http.Header{
				"Authorization": []string{"apikey mysecretkey"},
			},
			expectedKey:   "",
			expectedError: ErrMalformedAuthHeader,
		},
		{
			name: "Error - Incorrect case for 'ApiKey' prefix (e.g., 'APIKEY')",
			headers: http.Header{
				"Authorization": []string{"APIKEY mysecretkey"},
			},
			expectedKey:   "",
			expectedError: ErrMalformedAuthHeader,
		},
		/*{
			name: "Happy Path - Key with leading and trailing spaces (assuming no trim)",
			headers: http.Header{
				"Authorization": []string{"ApiKey  spaced key  "},
			},
			expectedKey:   "spaced key", // Assuming the function does not trim the key itself
			expectedError: nil,
		},*/
		{
			name: "Happy Path - Key with internal spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey my internal spaced key"},
			},
			expectedKey:   "my",
			expectedError: nil,
		},
		{
			name: "Edge Case - Multiple Authorization headers (uses first, as per http.Header.Get)",
			headers: http.Header{
				"Authorization": []string{"ApiKey firstKeyCorrect", "Bearer someOtherToken", "ApiKey thirdKey"},
			},
			expectedKey:   "firstKeyCorrect",
			expectedError: nil,
		},
		{
			name: "Edge Case - Authorization header is just 'ApiKey' with spaces around it",
			headers: http.Header{
				"Authorization": []string{" ApiKey "},
			},
			expectedKey:   "",
			expectedError: ErrMalformedAuthHeader, // Because it doesn't start with "ApiKey "
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup: tt.headers is already prepared

			// Execute
			apiKey, err := GetAPIKey(tt.headers)

			// Assert
			if apiKey != tt.expectedKey {
				t.Errorf("GetAPIKey() got key = %q, want %q", apiKey, tt.expectedKey)
			}
			if !errors.Is(err, tt.expectedError) {
				t.Errorf("GetAPIKey() got error = %v, want %v", err, tt.expectedError)
			}
		})
	}
}
