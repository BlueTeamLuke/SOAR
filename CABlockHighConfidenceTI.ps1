# Set your Azure account details
$tenantId = "$env:tenantId"
$appId = "$env:appId"
$appSecret = "$env:appSecret"
$subscriptionId = "$env:subscriptionId"
$resourceGroupName = "$env:resourceGroupName"
$workspaceName = "$env:workspaceName"

# Log Analytics Query
$query = @"
ThreatIntelligenceIndicator
| where ConfidenceScore == 100
| summarize by NetworkSourceIP
| extend NetworkIPWithSubnet = strcat(NetworkSourceIP, "/24")
| project NetworkIPWithSubnet
| limit 500000
"@

# Authenticate via service principle
$appSecretSecure = ConvertTo-SecureString -String $appSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($appId, $appSecretSecure)
Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $tenantId

# Select the subscription
Set-AzContext -Subscription $subscriptionId

# Get the workspace
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroupName -Name $workspaceName

# Set the request URI for the Log Analytics query
$requestUri = "https://api.loganalytics.io/v1/workspaces/$($workspace.CustomerId)/query"

# Set the request body for the Log Analytics query
$requestBody = @{
    "query" = $query
} | ConvertTo-Json

# Get the bearer token for the LAW API
$LAWtoken = (Get-AzAccessToken -ResourceUrl https://api.loganalytics.io).Token
Write-Output "Getting LAW token..."

# Set the request headers for the Log Analytics query
$requestHeaders = @{
    "Authorization" = "Bearer $LAWtoken"
    "Content-Type" = "application/json"
    "Prefer" = "ai.response-thinning=true"
}

# Send the request to the Log Analytics API
$response = Invoke-RestMethod -Method Post -Uri $requestUri -Body $requestBody -Headers $requestHeaders
Write-Output "Requesting list from LAW..."

# Get the list of IP addresses
$ipAddresses = $response.tables | ForEach-Object { $_.rows } | ForEach-Object { $_[0] } | Where-Object { $_ -ne "/24" }
Write-Output "IP list obtained!"

# Get the bearer token the MCAS API
$oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
$authBody = [Ordered] @{
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}
$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody
$MCAStoken = $authResponse.access_token
Write-Output "Getting MCAS token..."

# Set your headers and body for the MCAS API
$defenderHeaders = @{
    "Authorization" = "bearer $MCAStoken"
    "Content-Type" = "application/json"
}

# Get all subnets
$MCASUri = "https://<tenant_id>.<tenant_region>.portal.cloudappsecurity.com/api/v1/subnet/"
$checkResponse = Invoke-WebRequest -Uri $checkUri -Method Post -Headers $defenderHeaders
$checkResponseParsed = $checkResponse.Content | ConvertFrom-Json

# Search for the "TestTI" in the response
$testTISubnet = $checkResponseParsed.data | Where-Object { $_.name -eq "TestTI" }
Write-Output "Searching for TestTI list..."

if ($null -ne $testTISubnet) {
    # If it exists, delete it
    Write-Output "TestTI list found! Destroying list."
    $listId = $testTISubnet._id
    $deleteUri = "https://<tenant_id>.<tenant_region>.portal.cloudappsecurity.com/api/v1/subnet/$listId/"
    $deleteHeaders = @{"Authorization" = "bearer $MCAStoken"}
    $deleteResponse = Invoke-WebRequest -Uri $deleteUri -Method Delete -Headers $deleteHeaders
} else {
    Write-Output "TestTI list not found."
}
    
# Create the new list with the name "TestTI"
$defenderBody = @{
    "name" = "TestTI"
    "category" = 3
    "subnets" = $ipAddresses
    "tags" = @(
        "High Confidence TI"
    )
} | ConvertTo-Json

$defenderResponse = Invoke-RestMethod -Uri "<tenant_id>.<tenant_region>.portal.cloudappsecurity.com/api/v1/subnet/create_rule/" -Method Post -Headers $defenderHeaders -Body $defenderBody
Write-Output "TestTI list created! Script executed successfully."
