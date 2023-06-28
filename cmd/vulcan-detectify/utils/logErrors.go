package utils

import (
	"errors"
	"fmt"
)

// Exported Function
func PrintLogs(message string) {
	logger.Printf("%s", message)
}

// Custom Error Area

func CustomErrors(message string, statusCode int) error {
	if len(message) > 0 || statusCode != 0 {
		return &customErrorVar{
			Err:        errors.New(message),
			StatusCode: statusCode,
		}

	}
	return nil
}

func (ce *customErrorVar) Error() string {

	return fmt.Sprintf("\n[Utils] Error %d: %v \n", ce.StatusCode, ce.Err)
}
