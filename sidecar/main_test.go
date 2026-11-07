package main

import (
	"errors"
	"testing"
)

// The error the 1Password app returns for a client it dropped when it locked
// (taken from the SDK's own integration test).
const droppedClient = `an internal error occurred, please contact 1Password at support@1password.com or https://developer.1password.com/joinslack: invalid client id`

func TestRetriesOnceWithFreshClientWhenSessionIsLost(t *testing.T) {
	calls, resets := 0, 0
	data, err := withSession(func() (any, error) {
		calls++
		if calls == 1 {
			return nil, errors.New(droppedClient)
		}
		return "pong", nil
	}, func() { resets++ })

	if err != nil || data != "pong" || calls != 2 || resets != 1 {
		t.Fatalf("got data=%v err=%v calls=%d resets=%d, want pong, nil, 2, 1", data, err, calls, resets)
	}
}

func TestOtherErrorsAreNotRetried(t *testing.T) {
	calls, resets := 0, 0
	_, err := withSession(func() (any, error) {
		calls++
		return nil, errors.New("item not found")
	}, func() { resets++ })

	if err == nil || calls != 1 || resets != 0 {
		t.Fatalf("got err=%v calls=%d resets=%d, want an error, 1, 0", err, calls, resets)
	}
}

func TestGivesUpWhenTheFreshClientFailsToo(t *testing.T) {
	calls := 0
	_, err := withSession(func() (any, error) {
		calls++
		return nil, errors.New(droppedClient)
	}, func() {})

	if err == nil || calls != 2 {
		t.Fatalf("got err=%v calls=%d, want an error after 2 calls", err, calls)
	}
}
