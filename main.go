// Copyright 2015 Reed O'Brien <reed@reedobrien.com>.
// All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

const TIME_FMT = "2006-01-02 15:04:05 MST"

var (
	epochSec int64 // Representation of TOTP epoch in seconds
	err      error
	key      []byte // The decoded secret
	incr     func() // function to vary incrementing with window on hotp/totp
	secret   string // The hex or b32 secret
	otp      int64  // If an OTP is supplied for verification
	otpStr   string // the string representation of OTP
	nowSec   int64  // Representation of "now" in seconds

	// common flags are added in addFlags
	b32, verbose   *bool
	digits, window *int

	// cFlags is only here for usage()
	cFlag = flag.NewFlagSet("common", flag.ContinueOnError)

	// Flags
	hFlag   = flag.NewFlagSet("hotp", flag.ContinueOnError)
	counter = hFlag.Int64("c", 0, "HOTP counter Value")

	tFlag = flag.NewFlagSet("totp", flag.ContinueOnError)
	now   = tFlag.String("N", "", "Use this time as current time for TOTP")
	step  = tFlag.Int64("s", 30, "The time-step duration")
	epoch = tFlag.String("S", "1970-01-01 00:00:00 UTC", "When to start counting time-steps for TOTP")

	// Need a usage function since we don't build all flag sets unless the
	// program is called correctly.
	usage = func() {
		fmt.Fprintf(os.Stderr, "usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr,
			"\t%s [hotp|totp] <options> SECRET <OTP>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  SECRET is the hex or b32 encoded secret as a string\n")
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
	var (
		passcode string
		generate func() (string, error)
	)

	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "hotp":
		parseFlags(hFlag)
		generate = genHOTP
		incr = func() {
			*counter++
		}
		if *verbose {
			fmt.Println("Parsed hotp flags.")
			if *b32 {
				fmt.Println("Base 32 secret", secret)

			}
			if !*b32 {
				fmt.Println("Hex secret:", secret)
			}
			if otp != 0 {
				fmt.Println("OTP:", otp)
			}
			fmt.Println("Digits:", *digits)
			fmt.Println("Window size:", *window)
			fmt.Println("Start Counter:", *counter)
		}
	case "totp":
		parseFlags(tFlag)
		generate = genTOTP
		if *now == "" {
			nowSec = time.Now().UTC().Unix()
			*now = time.Unix(nowSec, 0).Format(TIME_FMT)
		} else {
			nowT, err := time.Parse(TIME_FMT, *now)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to parse now (-N): %s", err)
			}
			nowSec = nowT.UTC().Unix()
		}
		if *verbose {
			fmt.Println("Parsed totp flags.")
			if *b32 {
				fmt.Println("Base 32 secret", secret)

			}
			if !*b32 {
				fmt.Println("Hex secret:", secret)
			}
			if otp != 0 {
				fmt.Println("OTP:", otp)
			}
			fmt.Println("Digits:", *digits)
			fmt.Println("Window size:", *window)
			fmt.Println("Step size (seconds):", *step)
			fmt.Println("Start time:", *epoch)
			fmt.Println("Current time:", *now)
			fmt.Println("Counter:", nowSec / *step)

		}
		epochT, err := time.Parse(TIME_FMT, *epoch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse start time (-S): %s\n", err)
		}
		epochSec = epochT.UTC().Unix()
		incr = func() {
			nowSec += *step
		}

	default:
		usage()
	}

	key, err = getKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding secret: %s", err)
		os.Exit(1)
	}

	if otp > 0 {
		validate()
		os.Exit(0)
	}

	var max int64

	if *window > 0 {
		max = *counter + int64(*window)
	}
	if *window == 0 {
		max = 0
	}
	if *verbose {
		fmt.Println()
	}
	for i := int64(0); i <= max; i++ {
		passcode, err = generate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate passcode: %s:\n", err)
		}
		fmt.Println(passcode)
		incr()
	}
}

//// OTP functions

func genHOTP() (string, error) {
	var code uint32

	hash := hmac.New(sha1.New, key)

	err = binary.Write(hash, binary.BigEndian, *counter)
	if err != nil {
		return "", err
	}

	h := hash.Sum(nil)
	offset := h[19] & 0x0f

	trunc := binary.BigEndian.Uint32(h[offset : offset+4])
	trunc &= 0x7fffffff
	code = trunc % uint32(math.Pow(10, float64(*digits)))
	passcodeFormat := "%0" + strconv.Itoa(*digits) + "d"

	return fmt.Sprintf(passcodeFormat, code), nil
}

func genTOTP() (string, error) {
	var code string
	*counter = nowSec / *step
	code, err = genHOTP()
	return code, err
}

func validate() bool {
	fmt.Fprintf(os.Stderr, "Validation is not implemented yet.\n")
	os.Exit(1)
	if len(otpStr) != *digits {
		return false
	}

	return false
}

//// Helpers

func getKey() ([]byte, error) {
	var (
		key []byte
	)

	if *b32 {
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Err decoding secret: %s\n", err)
			return key, err
		}
	}
	if !*b32 {
		key, err = hex.DecodeString(secret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Err decoding secret: %s\n", err)
			return key, err
		}
	}
	return key, nil
}

//// arg parsing functions

func addFlags(f *flag.FlagSet) {
	// common flags add in flagParse method
	b32 = f.Bool("b", false, "Use b32 encoding instead of hex")
	digits = f.Int("d", 6, "The number of digits in the OTP")
	window = f.Int("w", 0, "Window of counter values to test when validating OTPs")
	verbose = f.Bool("v", false, "Explain what is being done.")
}

func getPositionalArgs(f *flag.FlagSet) {
	secret = strings.ToUpper(f.Arg(0))
	secret = strings.Replace(secret, " ", "", -1)
	if secret == "" {
		usage()
	}

	if *b32 {
		// repad base 32 strings if they are short.
		for len(secret) < 32 {
			secret = secret + "="
		}
	}

	otpStr := f.Arg(1)
	if otpStr != "" {
		otp, err = strconv.ParseInt(otpStr, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid OTP passcode: %s, err: %s", otpStr, err)
		}
	}
}

func parseFlags(f *flag.FlagSet) {
	addFlags(f)
	err = f.Parse(os.Args[2:])
	if err != nil {
		os.Exit(1)
	}
	getPositionalArgs(f)
}
