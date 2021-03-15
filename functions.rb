#encoding: UTF-8
 
#Launch Owasp ZAP 
def launch_owasp_zap
  #Set ZAP Path
  $zap_path = 'C:\ZAP\ZAP_2.4.3'
  #Go to ZAP Path
  Dir.chdir($zap_path){
 #Determine Operating System, kill JAVA instances and Start ZAP in deamon mode.
    if determine_os == 'windows'
      system("taskkill /im java.exe /f")
      system("taskkill /im javaw.exe /f")
      IO.popen("zap.bat -daemon")
    else
      system("pkill java")
      IO.popen("./zap.sh -daemon")
    end
    sleep 5
  }
  p "Owasp Zap launch completed"
  sleep 20
end
 
#Operating System Determination Method
def determine_os
  if (/cygwin|mswin|mingw|bccwin|wince|emx/ =~ RUBY_PLATFORM) != nil
    return 'windows'
  elsif (/darwin/ =~ RUBY_PLATFORM) != nil
    return 'mac'
  else
    return 'linux'
  end
end
