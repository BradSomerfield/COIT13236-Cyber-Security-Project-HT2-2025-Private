#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Import users from CSV and create unique AD accounts.

.DESCRIPTION
    This script reads users from a CSV, validates critical fields (FirstName, LastName, Role, Password),
    generates unique SamAccountNames for all roles, and handles user creation and group assignment 
    with detailed logging and error handling.

.NOTES
    CSV Format Example:
    FirstName,LastName,Password,Role,YearOfExit
    John,Doe,Temp1234,Student,2030
    Mary,Smith,Temp1234,Teacher,
#>

# --- Configuration Variables ---

# Path to input CSV file
$CsvPath = "C:\users.csv"

# Log file
$LogFile = "C:\AD_UserImport.log"

# CSV for exported results
$ExportCsv = "C:\AD_ImportedUsers.csv"

# Domain Suffix (Change 'rebeladmin.net' to your domain)
$DomainSuffix = "rebeladmin.net"

# --- Script Start ---

# Import the ActiveDirectory module (ensures it's loaded)
Import-Module ActiveDirectory -ErrorAction Stop

# Start logging
"--- Import started: $(Get-Date) ---" | Out-File $LogFile -Append
"Domain Suffix: $DomainSuffix" | Out-File $LogFile -Append

# Array to store results for export
$Results = @()

# Load CSV data and filter out rows with missing mandatory data
$UsersToProcess = Import-Csv $CsvPath | Where-Object { 
    $_.FirstName -and $_.LastName -and $_.Password -and $_.Role 
}

# Check if any users are left after filtering
if ($UsersToProcess.Count -eq 0) {
    "ERROR: No valid user data found in CSV after checking for FirstName, LastName, Password, and Role." | Out-File $LogFile -Append
}

$UsersToProcess | ForEach-Object {
    $User = $_ # Shorter alias for clarity
    
    # Initialize variables for the current user
    $SamAccountName = $null
    $ID = $null
    $OU = $null
    $Group = $null
    $UPN = $null
    $DisplayName = "$($User.FirstName) $($User.LastName)"
    $UserStatus = "Failed" 
    $ErrorDetails = "Script not yet processed"
    $ExistingUser = $null

    try {
        # --- 1. Determine User Type, OU, and Group & Generate Unique SamAccountName ---
        switch ($User.Role) {
            "Student" {
                if (-not $User.YearOfExit) {
                    throw "YearOfExit missing for student '$DisplayName'"
                }
                
                $OU = "OU=Students,DC=rebeladmin,DC=net"
                $Group = "Students_Group"

                # Student uniqueness: YearOfExit + random number
                do {
                    $Rand = Get-Random -Minimum 1000 -Maximum 9999
                    $SamAccountName = "$($User.YearOfExit)$Rand"
                    
                    # Check AD for existence
                    $ExistingUser = Get-ADUser -Filter { SamAccountName -eq $SamAccountName } -ErrorAction SilentlyContinue
                    
                    # Add a small delay to mitigate rare AD replication race conditions
                    if ($ExistingUser) {
                        Start-Sleep -Milliseconds 250 
                    }
                } while ($ExistingUser)
                
                # EmployeeID is the unique student number
                $ID = $SamAccountName
            }
            "Teacher" {
                if (-not $User.FirstName -or -not $User.LastName) {
                    throw "FirstName or LastName is missing for Teacher '$DisplayName'. Cannot generate SamAccountName."
                }
                
                # Generate primary SamAccountName: firstname-lastname
                $BaseSamAccountName = ("{0}-{1}" -f $User.FirstName, $User.LastName).ToLower()
                
                # Teacher uniqueness: Check for duplicates and append a number if necessary
                $i = 0
                do {
                    $SamAccountName = $BaseSamAccountName
                    if ($i -gt 0) {
                        # Append a number (e.g., mary-smith1)
                        $SamAccountName = "$BaseSamAccountName$i"
                    }
                    $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
                    $i++
                } while ($ExistingUser)
                
                $ID = $SamAccountName
                $OU = "OU=Teachers,DC=rebeladmin,DC=net"
                $Group = "Teachers_Group"
            }
            "Staff" {
                if (-not $User.FirstName -or -not $User.LastName) {
                    throw "FirstName or LastName is missing for Staff '$DisplayName'. Cannot generate SamAccountName."
                }
                
                # Generate primary SamAccountName: firstname.lastname
                $BaseSamAccountName = ("{0}-{1}" -f $User.FirstName, $User.LastName).ToLower()
                
                # Staff uniqueness: Check for duplicates and append a number if necessary
                $i = 0
                do {
                    $SamAccountName = $BaseSamAccountName
                    if ($i -gt 0) {
                        # Append a number (e.g., sam.lee1)
                        $SamAccountName = "$BaseSamAccountName$i"
                    }
                    $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
                    $i++
                } while ($ExistingUser)

                $ID = $SamAccountName
                $OU = "OU=Staff,DC=rebeladmin,DC=net"
                $Group = "Staff_Group"
            }
            Default {
                throw "Unknown Role '$($User.Role)' for user '$DisplayName'"
            }
        }
        
        # --- 2. Create AD User (Proceed only if a unique SamAccountName was generated) ---
        
        if ($SamAccountName) {
            
            $UPN = "$SamAccountName@$DomainSuffix"
            Write-Output "Attempting to create user '$SamAccountName' ($($User.Role)) in OU '$OU'..." | Out-File $LogFile -Append

            $SecurePassword = ConvertTo-SecureString $User.Password -AsPlainText -Force
            
            # Use ErrorAction Stop to ensure any creation failure goes directly to the catch block
            New-ADUser `
                -Name $DisplayName `
                -GivenName $User.FirstName -Surname $User.LastName `
                -SamAccountName $SamAccountName `
                -UserPrincipalName $UPN `
                -AccountPassword $SecurePassword `
                -ChangePasswordAtLogon $true -Enabled $true `
                -Path $OU `
                -EmployeeID $ID `
                -ErrorAction Stop 

            Write-Output "Successfully created user '$SamAccountName'." | Out-File $LogFile -Append

            # --- 3. Add User to Group ---
            try {
                # Check for group existence (Stop on error if group identity lookup fails)
                $GroupExists = Get-ADGroup -Identity $Group -ErrorAction Stop
                
                Add-ADGroupMember -Identity $Group -Members $SamAccountName -ErrorAction Stop
                Write-Output "Added '$SamAccountName' to group '$Group'." | Out-File $LogFile -Append
                $UserStatus = "Success"
                $ErrorDetails = "N/A"
            }
            catch {
                Write-Output "WARNING: Failed to add '$SamAccountName' to group '$Group': $($_.Exception.Message)" | Out-File $LogFile -Append
                $UserStatus = "Success (Group Failed)"
                $ErrorDetails = "Group add failed: $($_.Exception.Message)"
            }
        } else {
            Write-Output "ERROR: SamAccountName could not be generated for '$DisplayName'. Skipping." | Out-File $LogFile -Append
        }

    }
    catch {
        # Capture error details and log them
        $ErrorDetails = $_.Exception.Message.Replace("`n", " ").Replace("`r", "")
        Write-Output "ERROR creating user '$DisplayName' ($($User.Role)): $ErrorDetails" | Out-File $LogFile -Append
    }
    
    # Store results for export
    $Results += [PSCustomObject]@{
        FirstName       = $User.FirstName
        LastName        = $User.LastName
        Role            = $User.Role
        YearOfExit      = $User.YearOfExit
        SamAccountName  = $SamAccountName
        EmployeeID      = $ID
        GroupAssigned   = $Group
        OU              = $OU
        Status          = $UserStatus
        ErrorDetails    = $ErrorDetails
    }
}

# Export all created users to CSV
$Results | Export-Csv $ExportCsv -NoTypeInformation -Force

"--- Import finished: $(Get-Date) ---" | Out-File $LogFile -Append