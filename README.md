# goathtool README

## Synopsis

goathtool attempts reproduces the functionality of nongnu.org's oathtool
<http://www.nongnu.org/oath-toolkit/man-oathtool.html>. How incompletely is to
be determined. The intent is to implement the functionality the primary author
uses most and then -- as time or PRs occur -- to fill in more of the features.
The author also intends to differ in implementation of defaults and invocation.

goathtool will only implement the short flags as the author intends to forgo 3rd
party libraries.

## Description

goathtool

Generate OATH one-time passwords (OTP).


## Examples

The following examples are borrowed/stolen from the oathtool man page and are
therefore: Copyright © 2013 Simon Josefsson. License GPLv3+: GNU GPL version 3
or later <http://gnu.org/licenses/gpl.html>.

The commands have been modified to use the syntax goathtool uses.

To generate the first event-based (HOTP) one-time password for an all-zero key:

    $ goathtool hotp 00
    328482
    $

Sometime you want to generate more than a single OTP.  To generate 10
additional event-based one-time pass‐ words, with the secret key used in the
examples of RFC 4226, use the -w (--window) parameter:

    $ goathtool hotp -w 10 3132333435363738393031323334353637383930
    755224
    287082
    359152
    969429
    338314
    254676
    287922
    162583
    399871
    520489
    403154
    $

In the last output, the counter for the first OTP was 0, the second OTP had a
counter of 1, and so on up to 10.

In order to use keys encoded in Base32 instead of hex, you may provide the -b (--base32) parameter:

    $ goathtool hotp -b -w 3 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    755224
    287082
    359152
    969429
    $

The tool ignore whitespace in base32 data and re-add padding if necessary, thus
you may supply keys format‐ ted like the one below.

    $ goathtool totp -b  "gr6d 5br7 25s6 vnck v4vl hlao re"
    977872
    $


To generate a particular OTP, use the -c (--counter) parameter to give the
exact position directly:

    $ goathtool hotp -c 5 3132333435363738393031323334353637383930
    254676
    $

To validate a HOTP one-time password supply the OTP last on the command line:

  	$ goathtool hotp -w 10 3132333435363738393031323334353637383930 969429
  	3
  	$

The output indicates the counter that was used.  It works by starting with
counter 0 and increment until it founds a match (or not), within the supplied
window of 10 OTPs.

The  tool  supports  time-variant one-time passwords, in so called TOTP mode.
Usage is similar, but --totp needs to be provided:

    $ goathtool totp 00
    943388
    $

Don't be alarmed if you do not get the same output, this is because the output
is time variant.  To  gener‐ ate a TOTP for a particular fixed time use the -N
(--now) parameter:

    $ goathtool totp -N "2008-04-23 17:42:17 UTC" 00
    974945
    $

The  format is a mostly free format human readable date string such as "Sun, 29
Feb 2004 16:21:42 -0800" or "2004-02-29 16:21:42" or even "next Thursday".  It
is the same used as the --date parameter of the  date(1) tool.

You may generate several TOTPs by specifying the --window parameter, similar to
how it works for HOTP.  The OTPs generated here will be for the initial time
(normally current time) and then each following time  step (e.g., 30 second
window).

    $ goathtool totp -w 5 00
	815120
    003818
    814756
    184042
    582326
    733842
    $

You  can  validate  a TOTP one-time password by supplying the secret and a
window parameter (number of time steps before or after current time):

    $ goathtool totp -w 5 00 `goathtool --totp 00`
    0 # NB: this currently returns the counter not the item in the window that was found.
    $

Similar when generating TOTPs, you can use a -N (--now) parameter to specify
the time to use instead of the current time:

    $  goathtool totp -d 8 -N "2005-03-18 01:58:29 UTC" -w 10000000 3132333435363738393031323334353637383930 89005924
    4115227 # NB: this also returns a different number also because it returns the counter not the window item that matched
    $

The previous test uses values from the TOTP specification  and  will  stress
test  the  tool  because  the expected window is around 4 million time-steps.

There are two system parameters for TOTP: the time-step size and the time
start.

By default the time-step size is 30 seconds, which means you get a new OTP
every 30 seconds.  You may mod‐ ify this with the -s (--time-step-size)
parameter:

    $ goathtool totp -s 45 00
    109841 # time based doesn't validate
    $

The values are valid ISO-8601 durations, see:
http://en.wikipedia.org/wiki/ISO_8601#Durations

The time start is normally 1970-01-01 00:00:00 UTC but you may change it using
the -S (--start-time):

    $ goathtool totp -S "1980-01-01 00:00:00 UTC" 00
    273884 # time based doesnt' validate
    $

To get more information about what the tool is using use the -v (--verbose)
parameter.  Finally, to  gener‐ ate the last TOTP (for SHA-1) in the test
vector table of draft-mraihi-totp-timebased-07 you can invoke the tool like
this:

    $ goathtool totp -v -N "2033-05-18 03:33:20 UTC" -d 8 3132333435363738393031323334353637383930
    Hex secret: 3132333435363738393031323334353637383930
    Base32 secret: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    Digits: 8
    Window size: 0
    Step size (seconds): 30
    Start time: 1970-01-01 00:00:00 UTC (0)
    Time now: 2033-05-18 03:33:20 UTC (2000000000)
    Counter: 0x3F940AA (66666666)

    69279037
    $

In the last one the authoer only outputs either the hex or base32 secret that is provided.

## To Do

 - [x] LICENSE
 - [x] COPYRIGHT
 - [x]  Flags - outline basic flags
  	- [x] common flags
		- [x] -b base32
		- [x] -d number of digits in the OTP
		- [x] -w window of counter values to test
  	- [x]  hotp flags
		- [x] -c counter
  	- [x]  totp flags
 		- [x] -s time-step duration
 		- [x] -N time to use as current time
		- [x] -S time to start counting steps from (epoch)
 - [x] subcommand switch (hotp, totp)
 - [x] implement hotp
 - [x] implement totp using hotp
 - [x] ignore whitespace
 - [x] autopad base32 strings
 - [ ] tests
 - [ ] examples
 - [ ] godoc
 - [ ] add relevant docs and installation to README
 - [ ] fix totp validation to return the item from the window that matched not the abused counter
 - [ ] don't abuse counter AKA refactor

