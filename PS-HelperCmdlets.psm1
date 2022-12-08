## PowerShell Helper Module/Cmdlets

Function Get-RandomPassword {
    <#
    .Synopsis
        Very straightforward password generator capable of generating secure strings or plaintext.
      
    .NOTES
        Name: Get-RandomPassword
        Author: terxleben
      
    .LINK
        <>
      
      
    .PARAMETER Length
        Optional; Sets length of generated password. 
        Default 18 characters.

    .PARAMETER NonAlphaNumericCount
        Optional; Sets the minimum of non alpha-numeric characters.
        Default is calculated to 1/4.

    .PARAMETER SearchRoot
        Optional; default is set to current users search root. Can be set explicitly by passing it a
        variable created with (New-Object System.DirectoryServices.DirectoryEntry).
      
    .EXAMPLE
        Example 1:
        Get-RandomPassword -Length 20 -NonAlphaNumericCount 10
      
        Description:
        Returns securestring, with a password of 20 characters long and 10 non-alphanumeric characters.

        Example 2:
        Get-RandomPassword -AsPlainText
      
        Description:
        Returns a plaintext, with a password of 18 characters long and 4 non-alphanumeric characters.
    #>
    param (
        [int] $Length = 18,
        [int] $NonAlphaNumericCount = $length*0.25,
        [switch] $AsPlainText
    )
    # Add Assembly for system web so we get the 
    [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    switch ($AsPlainText) {
        $true {
            Write-Warning "Warning: This password generated may be stored in session logs or otherwise. Remove parameter -AsPlainText to mitigate this."
            $Password = [System.Web.Security.Membership]::GeneratePassword($Length,$NonAlphaNumericCount)
        }
        $false {
            $Password = [System.Web.Security.Membership]::GeneratePassword($Length,$NonAlphaNumericCount) | ConvertTo-SecureString -AsPlainText -Force
            
        }
    }
    return $Password
}

Function Search-LDAP {
    <#
    .Synopsis
        By Default, searches an AD LDAP in the current users directory search root, for a specified
        object type of User or Computer with the specified name matching DisplayName or sAMAccountName.
        The use of LDAP wildcards in the Name parameter is fully supported. 
      
    .NOTES
        Name: Query-LDAP
        Author: terxleben
      
    .LINK
        <>
      
      
    .PARAMETER Name
        Required; search matched on displayname or sAMAccountName. LDAP Wildcards are fully supported.

    .PARAMETER Category
        Required; set's the LDAP search to User or Computer.

    .PARAMETER SearchRoot
        Optional; default is set to current users search root. Can be set explicitly by passing it a
        variable created with (New-Object System.DirectoryServices.DirectoryEntry).
      
    .EXAMPLE
        Example 1:
        Search-LDAP -Name "Contoso" -Category Computer
      
        Description:
        Returns an object with any computers with their displayname or sAMAccount being Contoso

        Example 2:
        Search-LDAP -Name "*Admin*" -Category User
      
        Description:
        Returns an object with any users with their displayname or sAMAccount containing 'Admin' anywhere within.
        Note this type of double wildcard query can be extremely expensive computationally on the LDAP server.
    #>
    param (
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet("User","Computer")] $Category,
        $SearchRoot = (New-Object System.DirectoryServices.DirectoryEntry)
    )
    $ADSISearcher = New-Object DirectoryServices.DirectorySearcher("(&(objectCategory=$Category)(|(cn=$Name)(samaccountname=$Name)))")
    $ADSISearcher.PropertiesToLoad.Clear()
    $null = $ADSISearcher.PropertiesToLoad.Add("cn")
    $null = $ADSISearcher.PropertiesToLoad.Add("SAMAccountName")
    $null = $ADSISearcher.PropertiesToLoad.Add("distinguishedname")
    $Results = $ADSISearcher.FindAll()

    if ($Results.count -ne 0) {
        $ResultObject = foreach ($result in $Results.Properties) {
            $result | out-null
            New-Object -TypeName psobject -Property @{
                sAMAccountName  = [string]$result.samaccountname;
                Name            = [string]$result.cn;
                DN              = [string]$result.distinguishedname
            }
        }
    }
    
    return $ResultObject
}

Function Get-PendingReboot {
    <#
    .Synopsis
        This will check to see if a server or computer has a reboot pending.
        For updated help and examples refer to -Online version.
      
    .NOTES
        Name: Get-PendingReboot
        Author: terxleben, modified from theSysadminChannel to fix some path handling
      
    .LINK
        <>
      
      
    .PARAMETER ComputerName
        By default it will check the local computer.
      
    .EXAMPLE
        Get-PendingReboot -ComputerName PAC-DC01, PAC-WIN1001
      
        Description:
        Check the computers PAC-DC01 and PAC-WIN1001 if there are any pending reboots.
    #>

        [CmdletBinding()]
        Param (
            [Parameter(
                Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
                Position=0
            )]

        [string[]]  $ComputerName = $env:COMPUTERNAME
        )


        BEGIN {}

        PROCESS {
            Foreach ($Computer in $ComputerName) {
                Try {
                    $PendingReboot = $false

                    $HKLM = [UInt32] "0x80000002"
                    $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"

                    if ($WMI_Reg) {
                        if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'RebootPending') {$PendingReboot = $true}
                        if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")).sNames -contains 'RebootRequired') {$PendingReboot = $true}
    
                        #Checking for SCCM namespace
                        $SCCM_Namespace = Get-WmiObject -Namespace ROOT\CCM\ClientSDK -List -ComputerName $Computer -ErrorAction Ignore
                        if ($SCCM_Namespace) {
                            if (([WmiClass]"\\$Computer\ROOT\CCM\ClientSDK:CCM_ClientUtilities").DetermineIfRebootPending().RebootPending -eq $true) {$PendingReboot = $true}
                        }

                        [PSCustomObject]@{
                            ComputerName  = $Computer.ToUpper()
                            PendingReboot = $PendingReboot
                        }
                    }
                } catch {
                    Write-Error $_.Exception.Message

                } finally {
                    #Clearing Variables
                    $null = $WMI_Reg
                    $null = $SCCM_Namespace
                }
            }
        }

        END {}
}

Function Get-LoggedOnUser {
    <#
    .SYNOPSIS
        This will check the specified machine to see all users who are logged on.
         
    .NOTES
        Name: Get-LoggedOnUser
        Author: terxleben, modified from theSysadminChannel to add robust error handling
         
    .LINK
        <>
         
    .PARAMETER ComputerName
        Specify a computername to see which users are logged into it.  If no computers are specified, it will default to the local computer.
         
    .PARAMETER UserName
        If the specified username is found logged into a machine, it will display it in the output.
         
    .EXAMPLE
        Get-LoggedOnUser -ComputerName Server01
        Display all the users that are logged in server01
         
    .EXAMPLE
        Get-LoggedOnUser -ComputerName Server01, Server02 -UserName jsmith
        Display if the user, jsmith, is logged into server01 and/or server02
         
         
    #>
         
        [CmdletBinding()]
            param(
                [Parameter(
                    Mandatory = $false,
                    ValueFromPipeline = $true,
                    ValueFromPipelineByPropertyName = $true,
                    Position=0
                )]
                [string[]] $ComputerName = $env:COMPUTERNAME,
         
         
                [Parameter(
                    Mandatory = $false
                )]
                [Alias("SamAccountName")]
                [string]   $UserName
            )
         
        BEGIN {}
         
        PROCESS {
            foreach ($Computer in $ComputerName) {
                try {
                    $Computer = $Computer.ToUpper()
                    $SessionList = quser /Server:$Computer 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        $UserInfo = foreach ($Session in ($SessionList | select -Skip 1)) {
                            $Session = $Session.ToString().trim() -replace '\s+', ' ' -replace '>', ''
                            if ($Session.Split(' ')[3] -eq 'Active') {
                                [PSCustomObject]@{
                                    ComputerName = $Computer
                                    UserName     = $session.Split(' ')[0]
                                    SessionName  = $session.Split(' ')[1]
                                    SessionID    = $Session.Split(' ')[2]
                                    SessionState = $Session.Split(' ')[3]
                                    IdleTime     = $Session.Split(' ')[4]
                                    LogonTime    = $session.Split(' ')[5, 6, 7] -as [string] -as [datetime]
                                }
                            } else {
                                [PSCustomObject]@{
                                    ComputerName = $Computer
                                    UserName     = $session.Split(' ')[0]
                                    SessionName  = $null
                                    SessionID    = $Session.Split(' ')[1]
                                    SessionState = 'Disconnected'
                                    IdleTime     = $Session.Split(' ')[3]
                                    LogonTime    = $session.Split(' ')[4, 5, 6] -as [string] -as [datetime]
                                }
                            }
                        }
         
                        if ($PSBoundParameters.ContainsKey('Username')) {
                            $UserInfo | Where-Object {$_.UserName -eq $UserName}
                            } else {
                            $UserInfo | Sort-Object LogonTime
                        }
                    } else {
                        $ErrorDetail = $SessionList.Exception.Message[1]
                        Switch -Wildcard ($SessionList) {
                            '*[1722]*' { 
                                $Status = 'Remote RPC not enabled'
                            }
                            '*[5]*' {
                                $Status = 'Access denied'
                            }
                            'No User exists for*' {
                                $Status = 'No logged on users found'
                            }
                            default {
                                $Status = 'Error'
                                $ErrorDetail = $SessionList.Exception.Message
                            }
                            }
                            Write-Warning -Message "$Status on computer: $computer`n$ErrorDetail"
                    }
                } catch {
                    Write-Error $_.Exception.Message
                }
            }
        }
         
        END {}
}

Function Send-ARP {
    <#
    .SYNOPSIS
        This will generate and send an ARP packet on the local LAN. Useful for identifying the MAC of a device, or if a device is silently using an IP.
        This does not have any remote functionality. Remember ARP is local to your NIC's subnet - this won't return relaible results if sending an ARP for an IP outside of your subnet - 
        it will most likely return results from your routing infrastructure.
         
    .NOTES
        Name: Send-ARP
        Author: terxleben
         
    .LINK
        <>
         
    .PARAMETER DstIpAddress
        The IP address to perform an ARP request for.
         
    .PARAMETER SrcIpAddress
        Optional; The source IP address to used for the ARP request. Limited use cases but the option is exposed in the arp call so available if needed.
         
    .EXAMPLE
        Send-ARP -DstIpAddress 192.168.1.10
        Returns an object with IP address, Physical (MAC) address, ARP status (True/False), and Description if an error occured.
        Ex output:
        IpAddress      PhysicalAddress   ArpSuccess Description
        ---------      ---------------   ---------- -----------
        192.168.11.10 AA:BC:DE:23:88:F1       True
         
    #>
    
    param( 
        [Parameter(ValueFromPipeline,mandatory=$true)]    
        [string]$DstIpAddress, 
        [string]$SrcIpAddress = 0 
    ) 
 
 
    $signature = '[DllImport("iphlpapi.dll", ExactSpelling=true)] public static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen);'
 
    Add-Type -MemberDefinition $signature -Name Utils -Namespace Network 
 
    try { 
        $DstIp = [System.Net.IPAddress]::Parse($DstIpAddress) 
        $DstIp = [System.BitConverter]::ToUInt32($DstIp.GetAddressBytes(), 0) 
    } catch { 
        Write-Error "Could not convert $($DstIpAddress) to an IpAddress type.  Please verify your value is in the proper format and try again." 
        break 
    } 
 
 
    if ($SrcIpAddress -ne 0) { 
        try { 
            $SrcIp = [System.Net.IPAddress]::Parse($SrcIpAddress) 
            $SrcIp = [System.BitConverter]::ToUInt32($SrcIp.GetAddressBytes(), 0) 
        } catch { 
            Write-Error "Could not convert $($SrcIpAddress) to an IpAddress type.  Please verify your value is in the proper format and try again." 
            break 
        } 
    } else { 
        $SrcIp = $SrcIpAddress 
    } 
 
 
    $New = New-Object PSObject -Property @{ 
        IpAddress = $DstIpAddress 
        PhysicalAddress = '' 
        Description = '' 
        ArpSuccess = $true 
    } | Select-Object IpAddress,PhysicalAddress,ArpSuccess,Description 
 
    $MacAddress = New-Object Byte[] 6 
    $MacAddressLength = [uint32]$MacAddress.Length 
 
    $Result = [Network.Utils]::SendARP($DstIp, $SrcIp, $MacAddress, [ref]$MacAddressLength) 
 
    if ($Result -ne 0) { 
        $New.Description =  "An error was returned from SendArp() with error code:  $($Result)" 
        $New.ArpSuccess = $false 
    } else { 
        $MacFinal = @() 
        foreach ($b in $MacAddress) { 
            $MacFinal += $b.ToString('X2') 
        } 
 
        $New.PhysicalAddress = ($MacFinal -join ':') 
    }  
    return $New
}

Function Get-Uptime {
    <#
    .Synopsis
        This will get the uptime for the computer(s). Defaults to local computer.
      
    .NOTES
        Name: Get-Uptime
        Author: terxleben
      
    .LINK
        <>
      
      
    .PARAMETER Computer
        By default it will check the local computer, otherwise pass it a single or array of computers names.
      
    .EXAMPLE
        Get-Uptime -ComputerName DC01,DC02
      
        Description:
        Return the uptime for the computers.
    #>
	[CmdletBinding()]
	param (
        [Parameter(ValueFromPipeline)]
        [string[]]$Computername = $env:computername
	)
    BEGIN {}

    PROCESS {
        foreach ($computer in $ComputerName) {
            try {
                if ($Computer -eq $env:computername) {
                    $BootTime = (gcim Win32_OperatingSystem).LastBootUpTime
		            $UpTime = ((get-date) - $BootTime)

                    [PSCustomObject]@{
                    ComputerName    = $Computer;
                    TotalDaysUp     = [math]::Round($UpTime.TotalDays,2);
                    Days            = $UpTime.Days;
                    Hours           = $UpTime.Hours;
                    Minutes         = $UpTime.Minutes;
                    BootTime        = $BootTime
	                }
	            } Else {
	    	        $results = invoke-command -computername $Computer -scriptblock {
                        $BootTime = (gcim Win32_OperatingSystem).LastBootUpTime
		                $UpTime = ((get-date) - $BootTime)

                        [PSCustomObject]@{
                        ComputerName    = $Computer;
                        TotalDaysUp     = [math]::Round($UpTime.TotalDays,2);
                        Days            = $UpTime.Days;
                        Hours           = $UpTime.Hours;
                        Minutes         = $UpTime.Minutes;
                        BootTime        = $BootTime
                        }
                    }
	            }    
            } catch {
                Write-Error $_.Exception.Message
            }
        }
    }

    END {}
}

Function Remove-Profile {
    <#
    .Synopsis
        This will remove one or more user profiles from one or more computers. Default removes provided users from current computer.
      
    .NOTES
        Name: Remove-Profile
        Author: terxleben
      
    .LINK
        <>
      
      
    .PARAMETER Computer
        By default it will remove profiles on the local computer, otherwise pass it a single or array of computers names.
      
    .EXAMPLE
        Remove-Profile -UserName 'Jenkins' -ComputerName DC01,DC02
      
        Description:
        Removes the profile for Jenkins on DC01 and DC02.
    #>

	[CmdletBinding()]
	param (
        [Parameter(ValueFromPipeline,mandatory=$false)]
        [string[]]$ComputerName = $env:computername,
	    [Parameter(ValueFromPipeline,mandatory=$true)]
        [string[]]$UserName
	)
	
    BEGIN {}

    PROCESS {
        foreach ($Computer in $ComputerName) {
            foreach ($User in $UserName) {
                if ($Computer -eq $env:computernmae) {
                    Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath.split('\')[-1] -eq $User } | Remove-CimInstance -verbose
                } else {
                    Get-CimInstance -ComputerName $Computer -Class Win32_UserProfile | Where-Object { $_.LocalPath.split('\')[-1] -eq $User } | Remove-CimInstance -verbose
                }
	        }
        }
    }

    END {}
}

Function Set-SMBSharesReadOnly {
    <#
    .Synopsis
        This will set all Non-Admin SMB shares of a computer to read only.
      
    .NOTES
        Name: Set-SMBSharesReadOnly
        Author: terxleben
      
    .LINK
        <>
      
      
    .PARAMETER Computer
        By default it will disable all shares on the local computer, otherwise pass it 
        a single or array of computers names to run it on remote computers.
      
    .EXAMPLE
        Set-SMBSharesReadOnly -ComputerName 'Jenkins'
      
        Description:
        Sets all non-admin SMB shares to read only on computer Jenkins.
    #>

	[CmdletBinding(SupportsShouldProcess)]
	param (
        [Parameter(ValueFromPipeline,mandatory=$false)]
        [string[]]$ComputerName = $env:computername
	)
	
    BEGIN {}

    PROCESS {
        foreach ($c in $ComputerName) {
            if ($c -eq $env:ComputerName) {
                foreach ($i in (gwmi -Class win32_share -filter "Type = 0")) {
                    foreach ($s in (Get-SmbShareAccess $i.name)) {
                        Grant-SmbShareAccess -Name $s.name -AccountName $s.AccountName -AccessRight Read -WhatIf:$WhatIfPreference
                    }
                }
            } Else {
                Invoke-Command -ComputerName $c -ArgumentList $WhatIfPreference {
                    import-module smbshare
                    foreach ($i in (gwmi -Class win32_share -filter "Type = 0")) {
                        foreach ($s in (Get-SmbShareAccess $i.name)) {
                            Grant-SmbShareAccess -Name $s.name -AccountName $s.AccountName -AccessRight Read -WhatIf:$using:WhatIfPreference
                        }
                    }
                }
            }
        }
    }

    END {}
}
