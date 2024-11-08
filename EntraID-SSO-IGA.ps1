<#
.DESCRIPTION
  This script identifies inactive application users based on the Entra-ID Sign-In logs.
.PARAMETER Param1
  Set the thresholdValue that will set the threshold for inactive users
.INPUTS
  <Does the script accept an input>
.OUTPUTS
  A log file in the temp directory of the user running the script
.NOTES
  Version:        1.0
  Author:         Marcel Nguyen
  Creation Date:  06.06.2024
  Purpose/Change: 
.EXAMPLE
  <Give multiple examples of the script if possible>
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$AppName,
    [string]$groupPreFix,
    [string]$groupnameKeyword,
    [string]$thresholdQuery
)

#date
$today = Get-Date -Format "dd-MM-yy"

#Path to save the CSV Export
$filePath = "C:\temp\$($AppName)_inactive_users_$($thresholdQuery)days_$($today).csv"

#Log Analytics Workspace ID
$WorkSpaceId = "*Insert your Workspace ID here*"

#connect AzAccount for Log Analytics
Connect-AzAccount 

#Connect Graph 
Connect-Graph 

# Define KQL query with a 90-day threshold
$query = @"
SigninLogs
| where TimeGenerated > ago($($thresholdQuery)d)
| where AppDisplayName contains '$($AppName)'
| summarize LatestSignIn = arg_max(TimeGenerated, *) by UserPrincipalName
| project UserPrincipalName, LatestSignIn
"@

# Execute the KQL query
$kqlQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query

# Extract results into a dictionary for easier lookups
$activeUsers = @{}
foreach ($result in $kqlQuery.Results) {
    $activeUsers[$result.UserPrincipalName] = $result.LatestSignIn
}

# KQL Query to store all latest sign-in per user past 550 days
$query2 = @"
SigninLogs
| where TimeGenerated > ago(550d)
| where AppDisplayName contains '$($AppName)'
| summarize LatestSignIn = arg_max(TimeGenerated, *) by UserPrincipalName
| project AppDisplayName, UserPrincipalName, LatestSignIn
"@

# Execute the KQL query
$kqlQuery2 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query2

# Create Table to store latest sign-ins past 550 days
$SignInDates550d = @{}
foreach ($result in $kqlQuery2.Results) {
    $SignInDates550d[$result.UserPrincipalName] = $result.LatestSignIn
}
# Create Table to store App Name per User
$AppDisplayNames = @{}
foreach ($result in $kqlQuery2.Results) {
    $AppDisplayNames[$result.UserPrincipalName] = $result.AppDisplayName
}

# Get app group(s)
$app_groups = Get-MgGroup -All | Where-Object { $_.DisplayName -match "$($groupPreFix)" -and $_.DisplayName -match "$($groupnameKeyword)" }

# Collect all app users into an array
$app_users = @()
foreach ($group in $app_groups) {
    $app_groups = Get-MgGroupMember -GroupId $group.Id -All
    Write-Host "Processing $($group.DisplayName)" -ForegroundColor Yellow

    foreach ($user in $app_groups) {
        $userDetails = Get-MgUser -UserId $user.Id
        Write-Host "Processing $($userDetails.UserPrincipalName)"
        $app_users += [PSCustomObject]@{
            UserPrincipalName = $userDetails.UserPrincipalName
        }
    }
}

# Remove duplicates as users can be assigned to multiple application groups
$unique_app_users = $app_users | Sort-Object -Unique -Property UserPrincipalName

Write-Host "$($AppName) users in groups: $($unique_app_users.count)"

# Initialize arrays for active and inactive users
$activeAppUsers = @()
$inactiveAppUsers = @()

foreach ($user in $unique_app_users) {
    if ($activeUsers.ContainsKey($user.UserPrincipalName)) {
        $lastSignIn = $activeUsers[$user.UserPrincipalName]
        $AppDisplayName = $AppDisplayNames[$user.UserPrincipalName]
        Write-Host "$($user.UserPrincipalName) is active in $($AppName)." #-ForegroundColor Green
        $activeAppUsers += [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            LatestSignIn      = $lastSignIn
            AppDisplayName    = $AppDisplayName
        }
    } 
    else {
        if ($SignInDates550d.ContainsKey($user.UserPrincipalName)) {
            $lastSignIn = $SignInDates550d[$user.UserPrincipalName]
        }
        else {
            $lastSignIn = "No sign-in record in the last 550 days"
        }
        $AppDisplayName = $AppDisplayNames[$user.UserPrincipalName]
        Write-Host "$($user.UserPrincipalName) has not logged in past $($thresholdQuery) days. Last sign-in date: $lastSignIn" #-ForegroundColor Red
        $inactiveAppUsers += [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            LatestSignIn      = $lastSignIn
            AppDisplayName    = $AppDisplayName
        }
    }
}

# Export inactive users with their last sign-in date to a CSV file
$inactiveAppUsers | Export-Csv -Path $filePath -NoTypeInformation


# Output the counts
Write-Host "Number of active users: $($activeAppUsers.Count)" #-ForeGroundColor Green
Write-Host "Number of inactive users: $($inactiveAppUsers.Count)" #-ForeGroundColor Red

Write-Host "CSV-File Exported to: $filePath" #-ForegroundColor DarkCyan



