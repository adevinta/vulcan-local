/*
Copyright 2022 Adevinta
*/

package testutil

func ErrToStr(err error) string {
	result := ""
	if err != nil {
		result = err.Error()
	}
	return result
}
