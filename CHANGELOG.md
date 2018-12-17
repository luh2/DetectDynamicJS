# Changelog

<a name="0.10"></a>
## v0.10 (Lance)
	- fix bug in hasAuthenticationCharacteristic
	- reduce amount of requests

<a name="0.9"></a>
## v0.9 (Buddy Holly)
	- fix bugs
	- improve speed
	
<a name="0.8"></a>
## v0.8 (Honey Bunny)
	- add xssi protection detection
	- fix POST/GET
	- further code clean up

<a name="0.7"></a>
## v0.7 (Captain Koons)
	- fix race condition
	- fix `consolidateDuplicateIssues`
	- handle basic auth
	- code clean up

<a name="0.6"></a>
## v0.6 (Marsellus Wallace)
	- issue a second request to reduce false positives
	- report authentication-based findings as (Medium, Firm)
	- report generic dynamic as (Information, Certain), might be removed in future version

<a name="0.5"></a>
## v0.5 (Jules Winnfield)
	- Bug fix

<a name="0.4"></a>
## v0.4 (Butch Coolidge)
	- False positive reduction
	- Fix bug with cached files

<a name="0.3"></a>
## v0.3 (Mia Wallace)
	- Checking also for scripts that don't have a file ending
	- Ignore Responses with Content-Length of 0
	- Also scan application/json, which generates more false positives, but catches mis-labelled JSONP
	- automatically request the non-authentication version of script

<a name="0.2"></a>
## v0.2 (Vincent Vega)
	- Fix Calculation Error in calculateHighlights


<a name="0.1"></a>
## v0.1 (Pumpkin)
	- Initial Version
