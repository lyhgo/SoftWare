#Set-ExecutionPolicy Unrestricted -Force
echo copy_over_start_unzip

7z x  "D:\SoftWare-master\sonarqubeandtool.7z" -o"D:\Tools\" * -y

echo set_eviriment_path

$SystemPath=[environment]::GetEnvironmentVariable("Path","Machine")
$SystemPath+="D:\Tools\sonar-scanner-msbuild-4.4.2.1543-net46;"
$env:Sonar_HOME="D:\Tools\sonarqube-6.7.6"
#$env:Path

#change environment with reg

#set regV=HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment

#reg add "%regV%" /v "Path" /t REG_EXPAND_SZ /d "%Path%" /f

#change environment with [environment]::SetEnvironmentvariable

[environment]::SetEnvironmentvariable("Path", "$SystemPath","Machine")
[environment]::SetEnvironmentvariable("Sonar_HOME", "$env:Sonar_HOME","Machine")

New-NetFirewallRule -DisplayName "Jre SE 1.8 TCP" -Direction Inbound -LocalPort Any -Protocol TCP -Action Allow -Program "$env:JAVA_HOME\jre\bin\java.exe"

New-NetFirewallRule -DisplayName "Jre SE 1.8 UDP" -Direction Inbound -LocalPort Any -Protocol UDP -Action Allow -Program "$env:JAVA_HOME\jre\bin\java.exe"


Start-Process "D:\Tools\sonarqube-6.7.6\bin\windows-x86-64\StartSonar.bat" -WindowStyle Normal