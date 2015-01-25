# goathtool README

## Synopsis

goathtool incompletely reproduces the functionality of nongnu.org's oathtool
<http://www.nongnu.org/oath-toolkit/man-oathtool.html>. How incompletely is to
be determined. The intent is to implement the functionality the primary author
uses most and then -- as time or PRs occur -- to fill in more of the features.
The author also intends to differ in implementation of defaults and invocation.

goathtool will only implement the short flags. The author intends to forgo 3rd
party libraries.

## Description

goathtool 

Generate OATH one-time passwords (OTP).




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
