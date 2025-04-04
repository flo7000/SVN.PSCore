### Overview
# Author: flo7000
# Last updated: 28 / 03 / 2025
# Special Functions: 
#   New-VulnerabilityNotification -> Creates a planner task with the vulnerability description and updates the task with the NIST link.
#   Convert-TableToKQLString -> Creates a table in a format that you can use to import in KQL (with let table_name = externaldata())

### Initialisations
#requires -version 7.0
#requires -modules Microsoft.Graph.Authentication, Microsoft.Graph.Planner, SqlServer
$DebugPreference = "SilentlyContinue" # Continue -> PowerShell will show the debug message. SilentlyContinue -> PowerShell will not show the message.
$ErrorActionPreference = "Stop"

function Add-PlannerTaskLink {
    param (
        [Parameter(Mandatory = $true)]
        [string] $taskId,

        [Parameter(Mandatory = $true)]
        [string] $encodedLink,

        [Parameter(Mandatory = $true)]
        [string] $alias,

        [Parameter(Mandatory = $true)]
        [string] $GraphToken

    )

    $taskDetails = Get-MgPlannerTaskDetail -PlannerTaskId $taskId
    $etag = $taskDetails.AdditionalProperties."@odata.etag"
    $uri = "https://graph.microsoft.com/v1.0/planner/tasks/$taskId/details"

    $body = @{
        previewType = "noPreview"
        references = @{
            "$encodedLink" = @{
                "@odata.type" = "#microsoft.graph.plannerExternalReference"
                alias = "$alias"
                type = "Other"
                previewPriority = " !"
            }
        }
    } | ConvertTo-Json -Depth 10

    $headers = @{
        "Authorization" = "Bearer $GraphToken"
        "Content-Type"  = "application/json"
        "Prefer"        = "return=representation"
        "If-Match"      = $etag
    }
    $response = Invoke-WebRequest -Uri $uri -Method Patch -Headers $headers -Body $body -UseBasicParsing

}

function New-MgPlannerTaskWithDescription {
    param (
    [Parameter(Mandatory = $true)]
    [string] $GraphToken,

    [Parameter(Mandatory = $true)]
    [string] $PlanID,

    [Parameter(Mandatory = $true)]
    [string] $BucketID,

    [Parameter(Mandatory = $true)]
    [string] $TaskTitle,

    [Parameter(Mandatory = $true)]
    [hashtable] $TaskDescription,

    [Parameter(Mandatory = $true)]
    [hashtable] $TaskAssignment,

    [Parameter(Mandatory = $true)]
    [string] $TaskPriority,

    [Parameter(Mandatory = $true)]
    [string] $TaskDueDate

    )
    $status = "NotStarted"
    $task = New-MgPlannerTask -planId $PlanID -bucketId $BucketID -title $TaskTitle -Details $TaskDescription  -Assignments $TaskAssignment -priority $TaskPriority -dueDateTime $TaskDueDate

    if ($task.id) {
        $status = "Success"
    } else {
        $status = "Failure"
    }
    
    $TaskID = $task.id
    return @{ TaskID = $TaskID; Status = $status }
}


function New-VulnerabilityNotification {
    param (
    [Parameter(Mandatory = $true)]
    [string] $GraphToken,

    [Parameter(Mandatory = $true)]
    [string] $PlanID,

    [Parameter(Mandatory = $true)]
    [string] $BucketID,

    [Parameter(Mandatory = $false)]
    [string[]] $AllCVEs,

    [Parameter(Mandatory = $true)]
    [string] $hostname,

    [Parameter(Mandatory = $true)]
    [hashtable] $taskDescription,

    [Parameter(Mandatory = $true)]
    [hashtable] $taskAssignment,

    [Parameter(Mandatory = $true)]
    [string] $severityLevel,

    [Parameter(Mandatory = $true)]
    [string] $taskPrio,

    [Parameter(Mandatory = $true)]
    [string] $daysToSolve,

    [Parameter(Mandatory = $false)]
    [string] $helpArtikelLink,

    [Parameter(Mandatory = $false)]
    [string] $helpArtikelAlias

    )

    $status = "NotStarted"

    $enddate = (Get-Date).AddDays($daysToSolve) 
    $dueDate = $enddate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    $taskTitle = "$severityLevel Vulnerabilities on $hostname"

    $TaskCreation = New-MgPlannerTaskWithDescription -GraphToken $graphToken -PlanID $planId -BucketID $bucketId -TaskTitle $taskTitle -TaskDescription $taskDescription -TaskAssignment $taskAssignment -TaskPriority $taskPrio -TaskDueDate $dueDate

    if($TaskCreation.status -eq "Success") {
        foreach($cve in $AllCVEs) {
            $link = "https%3A//nvd%2Enist%2Egov/vuln/detail/$cve"
            $alias = "$cve | NIST"
            Add-PlannerTaskLink -TaskId $TaskCreation.TaskID -encodedLink $link -Alias $alias -GraphToken $GraphToken
        }

        if ($helpArtikelLink -ne $null) {
            Add-PlannerTaskLink -TaskId $TaskCreation.TaskID -encodedLink $helpArtikelLink -Alias $helpArtikelAlias -GraphToken $GraphToken
        } else {
            Write-Output "Du hast keinen Help-Artikel angegeben! "
        }
        $status = "Success"

        Write-Output "Created planner task"
    }
    else {
        Write-Error "Failed to create Planner task."
        $status = "Failure"
    }
    
    return $status
}


function Invoke-DefenderATPQuery {
    param (
    [Parameter(Mandatory = $true)]
    [string] $Query,

    [Parameter(Mandatory = $false)]
    [string] $TimeSpan
    )
    $status = "NotStarted"

    # Authenticating through the managed identity and getting Token
    $url = $env:IDENTITY_ENDPOINT  
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]" 
    $headers.Add("X-IDENTITY-HEADER", $env:IDENTITY_HEADER) 
    $headers.Add("Metadata", "True") 
    $body = @{resource='https://api.securitycenter.microsoft.com'} 
    $script:accessToken = (Invoke-RestMethod $url -Method 'POST' -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $body ).access_token

    $headers = @{
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $accessToken"
    }

    $defenderATPurl = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
    $defenderATPqueryBody = ConvertTo-Json -InputObject @{ 'Query' = $Query }

    # Running the query using POST method
    $queryresult = Invoke-WebRequest -Method Post -Uri $defenderATPurl -Headers $headers -Body $defenderATPqueryBody -ErrorAction Stop -UseBasicParsing 
    $result = ($queryresult | ConvertFrom-Json).Results

    if($result.Count -ge 2) {
        $status = "Success"
    }
    else {
        Write-Error "Failed to get more than two entries while running your KQL Query"
        $status = "Failure"
    }

    return @{ Result = $result; Status = $status }

}

function Convert-TableToKQLString {
    param (
        [Parameter(Mandatory = $true)]
        [Array] $table,  
        
        [Parameter(Mandatory = $true)]
        [Array] $fields
    )
    
    $Entries = @()

    foreach ($row in $table) {
        $formattedFields = @()

        foreach ($field in $fields) {
            $value = $row.$field -replace '"', '""'  
            $formattedFields += "`"$value`""  
        }
        $Entries += ($formattedFields -join ", ")
    }

    $String = $Entries -join ",`n"
    return $String
}
