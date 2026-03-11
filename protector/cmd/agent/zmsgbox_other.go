//go:build !windows

package main

func messageBoxConfirmWindows(message string) bool {
	// Non-Windows platforms do not use native message box here.
	// Prompt will be handled by platform branches in main code.
	return false
}
