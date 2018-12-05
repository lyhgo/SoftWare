echo start-download
#从github下载命令行解压需要的文件以及软件包
#Set-ExecutionPolicy Unrestricted -Force
$client = new-object System.Net.WebClient
$client.DownloadFile("https://github.com/lyhgo/SoftWare/archive/master.zip","D:\master.zip")
$client.DownloadFile("https://github.com/lyhgo/SoftWare/raw/master/7-Zip/7z.exe","D:\7z.exe")
$client.DownloadFile("https://github.com/lyhgo/SoftWare/raw/master/7-Zip/7z.dll","D:\7z.dll")
#复制解压主键到系统工具目录使其生效
Xcopy D:\7z.exe C:\Windows\System32 /y
Xcopy D:\7z.dll C:\Windows\System32 /y
#解压软件包
echo start-unziping-SoftwarePageke
7z x  "D:\master.zip" -o"D:\" -y
#安装OpenSSH并设置环境变量
7z x  "D:\SoftWare-master\OpenSSH-Win32.zip" -o"$env:ProgramFiles" * -y
$SystemPath=[environment]::GetEnvironmentVariable("Path","Machine")
$SystemPath+="$env:ProgramFiles\OpenSSH-Win32;"
[environment]::SetEnvironmentvariable("Path", "$SystemPath","Machine")
New-NetFirewallRule -DisplayName "SSH TCP_in" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "SSH UDP_out" -Direction Inbound -LocalPort 22 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "SSH TCP_in" -Direction Outbound -LocalPort 22 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "SSH UDP_out" -Direction Outbound -LocalPort 22 -Protocol UDP -Action Allow
powershell.exe -File "$env:ProgramFiles\OpenSSH-Win32\install-sshd.ps1"
Xcopy "D:\SoftWare-master\authorized_keys" "C:\Users\qq729943146\.ssh\authorized_keys.*" /y
Xcopy "D:\SoftWare-master\ssh_config" "$env:ProgramData\ssh\ssh_config.*" /y
net start sshd