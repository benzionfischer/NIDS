package utils

import "time"

// Generic filter function
func Filter[T any](slice []T, predicate func(T) bool) []T {
	result := []T{}
	for _, item := range slice {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

// Generic Find function
func Find[T any](slice []T, predicate func(T) bool) (bool, T) {
	elements := Filter(slice, predicate)
	if len(elements) == 0 {
		var zero T
		return false, zero
	}

	return true, elements[0]
}

// RemoveElement removes the first occurrence of the specified value from the slice.
func RemoveElement[T comparable](slice []T, value T) []T {
	for i, v := range slice {
		if v == value {
			// Remove the element by slicing
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice // Return the original slice if the element is not found
}

// MaxTime returns the later of two timestamps
func MaxTime(t1, t2 time.Time) time.Time {
	if t1.After(t2) {
		return t1
	}
	return t2
}
