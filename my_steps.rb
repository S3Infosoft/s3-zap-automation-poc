#encoding: UTF-8
 
#Launch OWASP ZAP using our launch_owasp_zap method in "functions.rb"
Given(/^I launch owasp zap for a scan$/) do
  launch_owasp_zap
end
 
#Run our test scenario
When(/^I perform some journeys on my site$/) do
  visit ''
  page.driver.browser.manage.window.maximize
  find_by_id('q').set 'lg g4'
  find('button.grd2').click
  find_by_id('PrList').find('div.p', match: :first)
  find_by_id('pf1').set '100'
  find_by_id('pf2').set '1000'
  find('button.grd1').click
  find_by_id('PrList').find('li.firstRow', match: :first).find('div.p').click
  find('tr.first', match: :first)
  sleep 20
end
 
#Get security warnings then classify and print them
Then(/^I should be able to see security warnings$/) do
  #Get response from via RestClient framework method.
  response = JSON.parse RestClient.get "http://#{$zap_proxy}:#{$zap_proxy_port}/json/core/view/alerts"
  
  #Classify the alerts
  events = response['alerts']
  high_risks = events.select{|x| x['risk'] == 'High'}
  high_count = high_risks.size
  medium_count = events.select{|x| x['risk'] == 'Medium'}.size
  low_count = events.select{|x| x['risk'] == 'Low'}.size
  informational_count = events.select{|x| x['risk'] == 'Informational'}.size
 
  #Check high alert count and print them
  if high_count > 0
    high_risks.each { |x| p x['alert'] }
  end
 
  #Expect high alert count equal to 0
  expect(high_count).to eq 0
 
  #Print alerts with risk levels
  site = Capybara.app_host
  response = JSON.parse RestClient.get "http://#{$zap_proxy}:#{$zap_proxy_port}/json/core/view/alerts",
      params: { zapapiformat: 'JSON', baseurl: site }
  response['alerts'].each { |x| p "#{x['alert']} risk level: #{x['risk']}"}
end
