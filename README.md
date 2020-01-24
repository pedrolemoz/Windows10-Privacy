
# Guia de privacidade do Windows 10 - Atualização 1903

![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/nutella_1903.jpg)


## Introdução

O Windows 10 trouxe muitas preocupações sobre privacidade devido ao fato de possuir muitos recursos de telemetria e outras ferramentas online. Em resposta a essas preocupações, a Microsoft lançou [um documento explicando exatamente quais dados eles coletam](https://technet.microsoft.com/itpro/windows/configure/windows-diagnostic-data) e agora o Windows 10 ainda tem um [Diagnostic Data Viewer](https://www.microsoft.com/en-us/store/p/diagnostic-data-viewer/9n8wtrrsq8f7) . Quando a telemetria é definida como básica, essa coletas parecem bem legítimas (para aprimorar o sistema), mas, mesmo assim, se você não confia nelas, veja como impedir o Windows 10 de enviar seus dados à Microsoft.  
Última atualização: 5 de julho de 2019

**Importante:** Este procedimento não pode ser revertido sem reinstalar o Windows. Não siga este guia se:
-   Você não é um usuário experiente
-   Você precisa usar uma conta da Microsoft por qualquer motivo (fora do seu navegador)
-   Você precisa fazer o download de qualquer coisa da Windows Store (incluindo distribuições para um subsistema Linux, se quiser usá-lo)
-   Você precisa adicionar / remover contas de usuário no seu PC (novas contas não funcionarão corretamente)

Você está fazendo isso por sua própria conta e risco, não sou responsável por qualquer perdas ou danos de dados que possam ocorrer.

Vamos começar!

## Não use as configurações padrão

No final do processo de configuração, crie uma conta local, não use a Cortana e desative tudo nas configurações de privacidade.

![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1809_1.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1809_2.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1809_3.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1903_4.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1903_5.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1809_coll.jpg)

Se você já instalou o Windows com as configurações padrão, vá em Iniciar > Configurações > Privacidade para desativá-las. Você também deve acessar Conta e desconectar sua conta da Microsoft, pois impedirá que este guia funcione corretamente.

## Faça o download de todas as atualizações

Depois de chegar à área de trabalho, vá em Configurações > Atualizações e Segurança e baixe todas as atualizações. Reinicie e repita até que não haja mais atualizações disponíveis.  
Isso é importante porque o Windows Update pode interferir em nossas atividades.

![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/updates1903_1.jpg)  

Agora abra o aplicativo da loja e faça o download das atualizações dos aplicativos também. Novamente, isso é importante porque as atualizações interferem em nossas atividades. Isto pode levar algum tempo.

![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/updates1809_2.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/updates1809_3.jpg)  

Verifique se há atualizações várias vezes, porque não queremos que ele baixe coisas enquanto a removemos.

Agora que o sistema está totalmente atualizado, verifique se o Windows está ativado com sua licença (ou KMSPico). 

## Remova tudo que puder

Abra o menu Iniciar e remova todos os aplicativos. Alguns deles, como o Microsoft Edge, não terão uma opção de desinstalação: nós os removeremos mais tarde. 

O importante agora é remover todo o software dos fabricantes e os jogos pré-instalados, como Candy Crush e Minecraft.

Se você usou versões anteriores do Windows 10, notará que desta vez podemos remover mais coisas, como o Paint 3D, sem recorrer a gambiarra.

## Ferramentas

Você precisará do **Install_Wim_Tweak** . Faça o download [deste arquivo](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/install_wim_tweak.zip) , extraia-o para a área de trabalho e mova-o para ```C:\Windows\System32```

![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/iwt1809_extr.jpg)

Essa é uma ferramenta muito útil que nos permite remover os componentes do Windows com um único comando. Você pode excluí-lo do System32 quando terminar este guia.

- Precisamos de um prompt de comando, então clique em Iniciar, digite `cmd`e execute-o como administrador.

![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/cmd1809_1.jpg)

- Também precisaremos do PowerShell. Clique em Iniciar, digite `PowerShell`e execute-o como administrador.

![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/ps1809_1.jpg)

## Removendo o Windows Defender

No prompt de comando, digite os seguintes comandos:

```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
install_wim_tweak /o /c Windows-Defender /r
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
```
Isso levará de 1 a 2 minutos.  
Infelizmente, desde junho de 2018, o ícone Segurança do Windows no menu Iniciar não pode mais ser removido sem danificar o sistema.

Se o Windows avisar que o sistema está desprotegido, clique com o botão direito do mouse na notificação e oculte-a.

![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/wdend1803_1.jpg)

## Removendo recursos

Agora vamos remover quase todos os recursos da UWP no Windows. O único aplicativo UWP restante será o aplicativo de configurações. Se você instalar aplicativos UWP manualmente mais tarde (como jogos UWP crackeados), eles poderão não funcionar corretamente.

**Nota:** se alguns dos aplicativos reaparecerem após alguns minutos, é porque você não esperou que as atualizações terminassem. Você pode simplesmente removê-los novamente usando os mesmos comandos.

### Loja do Windows

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *store* | Remove-AppxPackage
```

Você pode ignorar qualquer erro que aparecer.  
No prompt de comando, digite:

```
install_wim_tweak /o /c Microsoft-Windows-ContentDeliveryManager /r
install_wim_tweak /o /c Microsoft-Windows-Store /r
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
sc delete PushToInstall
```

### Música, TV, ...

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
Get-WindowsPackage -Online | Where PackageName -like *MediaPlayer* | Remove-WindowsPackage -Online -NoRestart
```

**Programas alternativos**: [MPC-HC](https://mpc-hc.org/) , [VLC](https://www.videolan.org/vlc/) , [MPV](https://mpv.srsfckn.biz/)

### Xbox e DVR

No PowerShell, digite:
```
Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage
```

Você pode ignorar qualquer erro que aparecer.

No prompt de comando, digite:

```
sc delete XblAuthManager
sc delete XblGameSave
sc delete XboxNetApiSvc
sc delete XboxGipSvc
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /f
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /disable
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
```

Além disso, vá para Iniciar > Configurações > Jogos e desative tudo.

### Notas adesivas

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage
```

**Programas alternativos**: [Notebot](http://notebot.fdossena.com/)

### Mapas

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage
```

No prompt de comando, digite:

```
sc delete MapsBroker
sc delete lfsvc
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable
```

### Alarmes e Relógio

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage
Get-AppxPackage -AllUsers *people* | Remove-AppxPackage
```

Você pode ignorar qualquer erro que aparecer.

### Email, Calendário, ...

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage
Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage
```
Você pode ignorar qualquer erro que aparecer.

**Programas alternativos**: [Thunderbird](https://www.mozilla.org/thunderbird/)

### OneNote

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *onenote* | Remove-AppxPackage
```

### Fotos

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *photo* | Remove-AppxPackage
```

**Programas alternativos**: [JPEGView](https://sourceforge.net/projects/jpegview/), or the old Windows Photo Viewer

### Câmera

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *camera* | Remove-AppxPackage
```

Você pode ignorar qualquer erro que aparecer.

### Clima, Notícias, ...

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage
```

### Calculadora

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *calc* | Remove-AppxPackage
```
**Programas alternativos**: [SpeedCrunch](http://www.speedcrunch.org/)

### Gravador de Som

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *soundrec* | Remove-AppxPackage
```

**Programas alternativos**: [Audacity](http://www.audacityteam.org/)

### Microsoft Edge

Desde maio de 2019, o Edge não pode mais ser totalmente removido sem danificar o Windows Update. Podemos neutralizá-lo, mas o ícone ainda estará lá no menu Iniciar.

Clique com o botão direito do mouse no ícone Edge na barra de tarefas e o desafixe.

No PowerShell, digite:

```
taskkill /F /IM browser_broker.exe
taskkill /F /IM RuntimeBroker.exe
taskkill /F /IM MicrosoftEdge.exe
taskkill /F /IM MicrosoftEdgeCP.exe
taskkill /F /IM MicrosoftEdgeSH.exe
mv C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe_BAK
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
Get-WindowsPackage -Online | Where PackageName -like *InternetExplorer* | Remove-WindowsPackage -Online -NoRestart
```  

**Programas alternativos**:[Firefox](http://www.firefox.com/"), [Chromium](http://chromium.woolyss.com/), [Iridium Browser](https://iridiumbrowser.de), [Pale Moon](https://www.palemoon.org/)

### Suporte, Ajuda

No prompt de comando, digite:

```
install_wim_tweak /o /c Microsoft-Windows-ContactSupport /r
```

No PowerShell, digite:

```
Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage
```

Além disso, vá em Iniciar > Configurações > Aplicativos > Gerenciar recursos opcionais e remova o Suporte ao contato (se houver).

### Microsoft Quick Assist

No PowerShell, digite:

```
Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart
```

### Connect

No prompt de comando, digite:

```
install_wim_tweak /o /c Microsoft-PPIProjection-Package /r
```

### Telefone

No prompt de comando, digite:

```
Get-AppxPackage -AllUsers *phone* | Remove-AppxPackage
```

### Hello Face

No PowerShell, digite:

```
Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart
```

No prompt de comando, digite:

```
schtasks /Change /TN "\Microsoft\Windows\HelloFace\FODCleanupTask" /Disable
```

### Editar com 3D Paint / 3D Print

Agora é possível remover o 3D Paint e o 3D Print, mas eles esqueceram de remover a opção no menu de contexto quando você os remove. Para removê-lo, execute isso no prompt de comando:

```
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit" ') do (reg delete "%I" /f )
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print" ') do (reg delete "%I" /f )
```

### Restauração do sistema

No PowerShell, digite:

```
Disable-ComputerRestore -Drive "C:\"
vssadmin delete shadows /all /Quiet
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR " /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR " /t "REG_DWORD" /d "1" /f
schtasks /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable
```

### Reinicie!

Reinicie o sistema, e você está livre dos bloatwares.

## Desabilitando a Cortana

Com a atualização de aniversário, a Microsoft ocultou a opção de desativar a Cortana.

**Aviso**: Não tente remover o pacote da Cortana usando o ´´´install_wim_tweak´´´ ou o PowerShell, pois isso danificará a Pesquisa do Windows e você precisará reinstalar o sistema novamente!

Abra seu prompt de comando novamente e use este comando:

```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
```

Reinicie e a Cortana vai ser desabilitada. O ícone ainda estará lá, mas vai apenas para a pesquisa normal do Windows.

## Mais ajustes

Abra o prompt de comando novamente.

### Desativar o relatório de erros do Windows

No prompt de comando, digite:

```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
```

Removeremos o serviço mais tarde, mas, se uma atualização o reinstalar, isso manterá o pelo menos desativado.

### Sem atualizações forçadas

Isso notificará quando houver atualizações disponíveis e você decide quando instalá-las.  

No prompt de comando, digite:

```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f
```

### Desabilitando a verificação de licença

Por padrão, o Windows verifica sua licença toda vez que você liga o computador. O comando abaixo evita isso.

No prompt de comando, digite:

```
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f
```

### Desabilitando a sincronização

Isso realmente não afeta você se você não estiver usando uma Conta da Microsoft, mas pelo menos desabilitará as configurações de Sincronização nas Configurações.

No prompt de comando, digite:

```
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f
```

### Desabilitando as Dicas do Windows

No prompt de comando, digite:

```
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f
```

## Removendo a telemetria e outros serviços desnecessários

No prompt de comando, digite os seguintes comandos:

```
sc delete DiagTrack
sc delete dmwappushservice
sc delete WerSvc
sc delete OneSyncSvc
sc delete MessagingService
sc delete wercplsupport
sc delete PcaSvc
sc config wlidsvc start=demand
sc delete wisvc
sc delete RetailDemo
sc delete diagsvc
sc delete shpamsvc 
sc delete TermService
sc delete UmRdpService
sc delete SessionEnv
sc delete TroubleshootingSvc
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "wscsvc" ^| find /i "wscsvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"') do (reg delete %I /f)
sc delete diagnosticshub.standardcollector.service
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
```

Pressione ```Win + R```, digite ```regedit```, dê enter e navegue até HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services.  
Aqui, precisaremos encontrar as seguintes chaves:

- DPS
- WdiServiceHost
- WdiSystemHost
  
Essas chaves tem algumas permissões chatas. Para deletá-las, você deverá seguir o tutorial do GIF:

![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/delkey.gif)

Clique com o botão direito do mouse na chave e selecione Permissões, depois clique em Avançado, altere o Proprietário para o seu nome de usuário, e marque "Substituir proprietário em subcontêineres e objetos" e "Substituir tudo entradas de permissão de objeto filho com entradas de permissão herdáveis ​​deste objeto ", e se a herança estiver ativada, desative-a e converta-a em permissões explícitas, clique em aplicar, remova todas as entradas de permissão e adicione uma para o seu nome de usuário com Controle total, confirme tudo e exclua a chave. Repita o procedimento para as 3 chaves e você terá concluído.

### Tarefas agendadas

O Windows 10 possui uma enorme quantidade de tarefas agendadas que podem enviar alguns dados. Digite estes comandos no prompt de comando para removê-los:

```
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" 
```
Alguns deles podem não existir, mas está tudo bem.

## Toques finais

É necessário desativar o Windows Spotlight e outras "Sugestões" (são literalmente anúncios).

Vá para Iniciar > Configurações > Personalização > Tela de bloqueio:
	- Coloque a opção o plano de fundo como Imagem
	- Coloque a opção "Desativar fatos divertidos, dicas, truques e muito mais na tela de bloqueio" como desativado

Go to Personalização > Iniciar:
	- Coloque a opção "Mostrar sugestões ocasionalmente em Iniciar" como desativado

Volte em Configurações e vá para Sistema > Notificações e ações:
	- Coloque a opção "Obter dicas, truques e sugestões ao usar o Windows" como desativado
	- Coloque a opção "Mostre-me as boas-vindas do Windows ..." como desativado

Vá para Sistema > Multitarefa:
	- Coloque a opção "Mostrar sugestões ocasionalmente na linha do tempo" como desativado
 
Volte para Configurações e vá em Privacidade:
	- Em Geral, desative tudo
	- Em Histórico de atividades, desative tudo
	- Em Controle por Voz, desative tudo
	- Em Personalização de escrita a tinta..., desative tudo
	- Em Diagnósticos e comentários, coloque a opção "Permitir que aplicativos acessem informações de diagnóstico" como desativado

Volte para Configurações e vá em Pesquisar:
* Em Permissões e Histórico, desative tudo

Posteriormente, você poderá receber uma notificação de "Sugestões". Clique com o botão direito do mouse e desligue-o.

## Parabéns! Sua cópia do Windows agora está livre de bloatware!

As coisas poderão no futuro, e farei o possível para manter este guia atualizado. Desde maio de 2018, este guia funciona no Windows 10 Pro.

## O Windows pode reverter essas alterações?

Quando uma grande atualização é instalada, quase todas as alterações serão revertidas e você terá que repetir este procedimento. Grandes atualizações são lançadas cerca de duas vezes por ano.

## Tradução e adaptação:

[Pedro Lemos](https://github.com/pedrolemoz)
