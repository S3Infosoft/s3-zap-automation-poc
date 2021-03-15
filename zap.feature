
#encoding: UTF-8
 
Feature: Run an OWASP ZAP screening
  As a user
  I want to run a security screening for my site
  In order to have a secure application
 
  Scenario: Run security tests
    Given I launch owasp zap for a scan
    When I perform some journeys on my site
    Then I should be able to see security warnings
