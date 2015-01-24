// Copyright 2015 Reed O'Brien <reed@reedobrien.com>.
// All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"time"
)

var (
	err    error
	secret string // The hex or base32 secret
	// otp string 	// If a value is supplied for varification

	//// Flags
	// common flags add in flagParse method
	// base32 = flag.Bool("b", false, "Use base32 encoding instead of hex")
	// digits = flag.Int("d", 6, "The number of digits in the OTP")
	// window = flag.Int("w", 1, "Window of counter values to test when validating OTPs")

	hFlag   = flag.NewFlagSet("hotp", flag.ContinueOnError)
	counter = hFlag.Int64("c", 0, "HOTP counter Value")

	tFlag = flag.NewFlagSet("totp", flag.ContinueOnError)
	now   = tFlag.Int64("N", time.Now().UTC().Unix(), "Use this time as current time for TOTP")
	step  = tFlag.Int64("s", 30, "The time-step duration")
	epoch = tFlag.String("S", "1970−01−01 00:00:00 UTC", "When to start counting time-steps for TOTP")
)

func main() {
	fmt.Print("code appears here")
}
