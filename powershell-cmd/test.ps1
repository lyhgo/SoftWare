echo 7z_copy

Xcopy D:\SoftWare-master\7-Zip\7z.exe C:\Windows\System32 /y

Xcopy D:\SoftWare-master\7-Zip\7z.dll C:\Windows\System32 /y

echo jdk_zip_copy

echo copy_over_start_unzip

#7z x  "D:\SoftWare-master\Java.rar" -o"$env:ProgramFiles" * -y

#7z x  "D:\SoftWare-master\apache-tomcat-8.5.35-and-jenkins.zip" -o"D:\Tools\" * -y

echo set_eviriment_path

$SystemPath=[environment]::GetEnvironmentVariable("Path","Machine")
$SystemPath+="C:\Program Files\Java\jdk1.8.0_191;"
$env:JAVA_HOME="C:\Program Files\Java\jdk1.8.0_191"
#$env:Path

#change environment with reg

#set regV=HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment

#reg add "%regV%" /v "Path" /t REG_EXPAND_SZ /d "%Path%" /f

#change environment with [environment]::SetEnvironmentvariable

[environment]::SetEnvironmentvariable("Path", "$SystemPath","Machine")
[environment]::SetEnvironmentvariable("JAVA_HOME", "$env:JAVA_HOME","Machine")

New-NetFirewallRule -DisplayName "Java SE 1.8 TCP" -Direction Inbound -LocalPort Any -Protocol TCP -Action Allow -Program "$env:JAVA_HOME\bin\java.exe"

New-NetFirewallRule -DisplayName "Java SE 1.8 UDP" -Direction Inbound -LocalPort Any -Protocol UDP -Action Allow -Program "$env:JAVA_HOME\bin\java.exe"

cd "D:\Tools\apache-tomcat-8.5.35\bin"

D:\Tools\apache-tomcat-8.5.35\bin\startup.bat

read-host