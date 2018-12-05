echo setidentify

$secpasswd = ConvertTo-SecureString "LUOyuanhang)(*15" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("qq729943146", $secpasswd)
echo connect
#Enter-PSSession 52.231.167.215 -Credential $mycreds
$session = new-pssession 52.231.162.103 -Credential $mycreds
echo connect-over
echo start
echo "install OpenSSH"
#Invoke-Command -Session $session -FilePath "D:\powershell-cmd\TestEnvirmentSetUpCmd.ps1"
echo "transport file"
#scp D:\Java.rar qq729943146@52.231.162.103:D:\SoftWare-master\Java.rar
echo "install jenkins and jdk"
#Invoke-Command -Session $session -FilePath "D:\powershell-cmd\TestEnvirmentSetUpCmd2.ps1"
echo "transport file"
#scp D:\sonarqubeandtool.7z qq729943146@52.231.162.103:D:\SoftWare-master\sonarqubeandtool.7z
echo "install SonarQube"
#Invoke-Command -Session $session -FilePath "D:\powershell-cmd\TestEnvirmentSetUpCmd3.ps1"
echo "install visdio studio"
#Invoke-Command -Session $session -FilePath "D:\powershell-cmd\TestEnvirmentSetUpCmd4.ps1"
echo "open iis"
Invoke-Command -Session $session -FilePath "D:\powershell-cmd\setupIIS.ps1"

echo over
