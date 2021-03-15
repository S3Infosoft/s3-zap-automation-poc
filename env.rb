#encoding: UTF-8
require 'cucumber'
require 'rspec'
require 'selenium-webdriver'
require 'rest-client'
require 'capybara'
require 'capybara/dsl'
 
#Define global variables
$zap_proxy = "localhost"
$zap_proxy_port = 8095
 
#Below lines are our driver profile settings to reach internet through a proxy 
#You can set security=true as environment variable or declare it on command window
if ENV['security'] == "true"
  Capybara.register_driver :selenium do |app|
    profile = Selenium::WebDriver::Firefox::Profile.new
    profile["network.proxy.type"] = 1
    profile["network.proxy.http"] = $zap_proxy
    profile["network.proxy.http_port"] = $zap_proxy_port
    Capybara::Selenium::Driver.new(app, :profile => profile)
  end
end
 
#Screenshot operations
$screenshot_counter = 0
Capybara.save_and_open_page_path = File.expand_path(File.join(File.dirname(__FILE__), "../screenshots/"))
 
#Capybara settings
Capybara.run_server = false
Capybara.default_driver = :selenium #Use Selenium as Driver
Capybara.javascript_driver = :selenium #Use Selenium as JS Driver
Capybara.default_selector = :css #Defatult Selector methos is CSS
Capybara.default_max_wait_time = 15 #Wait time is 15 seconds
Capybara.ignore_hidden_elements = false #Do not ignore hidden elements
Capybara.exact = true #All is expressions match exactly (Exact Match/Ignores substring matches)
Capybara.app_host = 'http://www.akakce.com' #Our test site
World(Capybara::DSL)
 
ENV['NO_PROXY'] = ENV['no_proxy'] = '127.0.0.1'
if ENV['APP_HOST']
  Capybara.app_host = ENV['APP_HOST']
  if Capybara.app_host.chars.last != '/'
    Capybara.app_host += '/'
  end
end
 
FIRST_ACCOUNT_SUFFIX = 5001
$delete_enabled = true
$environment = 'qa'
