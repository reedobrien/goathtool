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

var (
	err    error
	secret string // The hex or b32 secret
	otp    string // If an OTP is supplied for verification

	// common flags are add in addFlags
	b32, verbose   *bool
	digits, window *int

	// cFlags is only here for usage()
	cFlag = flag.NewFlagSet("common", flag.ContinueOnError)

	// Flags
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
	var passcode string
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "hotp":
		parseFlags(hFlag)
		passcode, err = genHOTP()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate passcode: %s:\n", err)
		}
	case "totp":
		parseFlags(tFlag)
		os.Exit(1)
	default:
		usage()
	}

	fmt.Println(passcode)
}

// OTP functions

func genHOTP() (string, error) {
	var (
		code uint32
		key  []byte
	)
	key, err := getKey()
	if err != nil {
		return "", nil
	}
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

// Flag functions

func addFlags(f *flag.FlagSet) {
	// common flags add in flagParse method
	b32 = f.Bool("b", false, "Use b32 encoding instead of hex")
	digits = f.Int("d", 6, "The number of digits in the OTP")
	window = f.Int("w", 1, "Window of counter values to test when validating OTPs")
	verbose = f.Bool("v", false, "Explain what  is being done.")
}

func getPositionalArgs(f *flag.FlagSet) {
	secret = strings.ToUpper(f.Arg(0))
	secret = strings.Replace(secret, " ", "", -1)
	if secret == "" {
		usage()
	}
	// TODO: Also validate that it is long enough to be hex or b32?
	otp = f.Arg(1)
}

func parseFlags(f *flag.FlagSet) {
	addFlags(f)
	err = f.Parse(os.Args[2:])
	if err != nil {
		os.Exit(1)
	}
}
