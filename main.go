// Copyright 2015 Reed O'Brien <reed@reedobrien.com>.
// All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

var (
	err    error
	secret string // The hex or base32 secret
	otp    string // If an OTP is supplied for verification

	// common flags are add in addFlags
	base32         *bool
	digits, window *int

	// cFlags is only here for usage()
	cFlag = flag.NewFlagSet("common", flag.ContinueOnError)

	//// Flags
	hFlag   = flag.NewFlagSet("hotp", flag.ContinueOnError)
	counter = hFlag.Int64("c", 0, "HOTP counter Value")

	tFlag = flag.NewFlagSet("totp", flag.ContinueOnError)
	now   = tFlag.Int64("N", time.Now().UTC().Unix(), "Use this time as current time for TOTP")
	step  = tFlag.Int64("s", 30, "The time-step duration")
	epoch = tFlag.String("S", "1970−01−01 00:00:00 UTC", "When to start counting time-steps for TOTP")

	// Need a usage function since we don't build all flag sets unless the
	// program is called correctly.
	usage = func() {
		fmt.Fprintf(os.Stderr, "usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr,
			"\t%s [hotp|totp] <options> SECRET <OTP>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  SECRET is the hex or base32 encoded secret as a string\n")
		fmt.Fprintf(os.Stderr, "  OTP is a one-time password to validate.\n")
		fmt.Fprintf(os.Stderr, "Common options:\n")
		addFlags(cFlag)
		cFlag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "hotp options:\n")
		hFlag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "totp options:\n")
		tFlag.PrintDefaults()
		os.Exit(1)
	}
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "hotp":
		parseFlags(hFlag)
	case "totp":
		parseFlags(tFlag)
	default:
		usage()
	}

	fmt.Println("code appears here")
}

func addFlags(f *flag.FlagSet) {
	// common flags add in flagParse method
	base32 = f.Bool("b", false, "Use base32 encoding instead of hex")
	digits = f.Int("d", 6, "The number of digits in the OTP")
	window = f.Int("w", 1, "Window of counter values to test when validating OTPs")
}

func parseFlags(f *flag.FlagSet) {
	addFlags(f)
	err = f.Parse(os.Args[2:])
	if err != nil {
		usage()
	}
}
