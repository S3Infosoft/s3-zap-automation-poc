# Run ZAP from a Markdown Specification

This is an example of how you can run ZAP from a Markdown Specification

## Open URL with OWASP ZAP

This is a scenario that starts OWASP ZAP

* Start ZAP and Open URL "http://www.example.com"

## Login to web Application

* Login using username and password against target uri "http://www.example.com/login"



## Spider the target

* Run spider against target "http://www.example.com"
* Get spider status

## Ajax spider Application

* Run Ajax spider against target "http://www.exaple.com"
* Get Ajax results

## Run authenticated passive scan

* Start passive scan against "http://www.exaple.com"
* Get passive sacn results

## Active Scan against the Target URL

This is a scenario that active scans the target URL with OWASP ZAP's Active Scanner

* Start Active Scan against "http://www.paygatway.in"
* Get Active Scan status


## Get csrf tokens

* Fetch csrf tokens 
* print csrf token

## Get parameters 

* get parameters from results
* print name of parameters

## Run Active scan on parameters

* run active scan against each parameter
* get results


## Generate ZAP Report

This is a scenario that generates a report based on the format provided

* Export ZAP Report for "Paygatway" in "HTML" format with "testfire-app.html" for "we45" with "Testfire DAST Report"

## Close ZAP

* Shutdown ZAP
