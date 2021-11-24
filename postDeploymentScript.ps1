param(
    [string]$tenant_id,
    [string]$user_id,
    [string]$client_id,
    [string]$client_secret,
    [string]$purview_account,
    [string]$vault_uri,
    [string]$admin_login,
    [string]$sql_secret_name,
    [string]$subscription_id,
    [string]$resource_group,
    [string]$location,
    [string]$sql_server_name,
    [string]$sql_db_name,
    [string]$storage_account_name,
    [string]$adf_name,
    [string]$adf_principal_id,
    [string]$adf_pipeline_name,
    [string]$managed_identity
)

# Variables
$scan_endpoint = "https://${purview_account}.scan.purview.azure.com"
$catalog_endpoint = "https://${purview_account}.catalog.purview.azure.com"
$pv_endpoint = "https://${purview_account}.purview.azure.com"

# [POST] Token
function getToken([string]$tenant_id, [string]$client_id, [string]$client_secret) {
    $uri = "https://login.windows.net/${tenant_id}/oauth2/token"
    $body = @{
        "grant_type" = "client_credentials"
        "client_id" = $client_id
        "client_secret" = $client_secret
        "resource" = "https://purview.azure.net"
    }
    $params = @{
        ContentType = "application/x-www-form-urlencoded"
        Headers = @{"accept"="application/json"}
        Body = $body
        Method = "POST"
        URI = $uri
    }
    
    $token = Invoke-RestMethod @params
    
    Return "Bearer " + ($token.access_token).ToString()
}

# [PUT] Data Source
function putSource([string]$token, [hashtable]$payload) {
    $dataSourceName = $payload.name
    $uri = "${scan_endpoint}/datasources/${dataSourceName}?api-version=2018-12-01-preview"
    $params = @{
        ContentType = "application/json"
        Headers = @{"Authorization"=$token}
        Body = ($payload | ConvertTo-Json)
        Method = "PUT"
        URI = $uri
    }
    $retryCount = 0
    $response = $null
    while (($null -eq $response) -and ($retryCount -lt 3)) {
        try {
            $response = Invoke-RestMethod @params
        }
        catch {
            Write-Host "[Error] Unable to putSource."
            Write-Host "Token: ${token}"
            Write-Host "URI: ${uri}"
            Write-Host ($payload | ConvertTo-Json)
            Write-Host "Response:" $_.Exception.Response
            Write-Host "Exception:" $_.Exception

            $result = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($result)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host $responseBody

            $retryCount += 1
            $response = $null
        }
    }
    Return $response
}

# [PUT] Key Vault
function putVault([string]$token, [hashtable]$payload) {
    $randomId = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 3 |ForEach-Object{[char]$_})
    $keyVaultName = "keyVault-${randomId}"
    $uri = "${scan_endpoint}/azureKeyVaults/${keyVaultName}"
    $params = @{
        ContentType = "application/json"
        Headers = @{"Authorization"=$token}
        Body = ($payload | ConvertTo-Json)
        Method = "PUT"
        URI = $uri
    }
    $response = Invoke-RestMethod @params
    Return $response
}

# [PUT] Credential
function putCredential([string]$token, [hashtable]$payload) {
    $credentialName = $payload.name
    $uri = "${pv_endpoint}/proxy/credentials/${credentialName}?api-version=2020-12-01-preview"
    $params = @{
        ContentType = "application/json"
        Headers = @{"Authorization"=$token}
        Body = ($payload | ConvertTo-Json -Depth 9)
        Method = "PUT"
        URI = $uri
    }
    $response = Invoke-RestMethod @params
    Return $response
}

# [PUT] Scan
function putScan([string]$token, [string]$dataSourceName, [hashtable]$payload) {
    $scanName = $payload.name
    $uri = "${scan_endpoint}/datasources/${dataSourceName}/scans/${scanName}"
    $params = @{
        ContentType = "application/json"
        Headers = @{"Authorization"=$token}
        Body = ($payload | ConvertTo-Json -Depth 9)
        Method = "PUT"
        URI = $uri
    }
    $response = Invoke-RestMethod @params
    Return $response
}

# [PUT] Run Scan
function runScan([string]$token, [string]$datasourceName, [string]$scanName) {
    $uri = "${scan_endpoint}/datasources/${datasourceName}/scans/${scanName}/run?api-version=2018-12-01-preview"
    $payload = @{ scanLevel = "Full" }
    $params = @{
        ContentType = "application/json"
        Headers = @{"Authorization"=$token}
        Body = ($payload | ConvertTo-Json)
        Method = "POST"
        URI = $uri
    }
    $response = Invoke-RestMethod @params
    Return $response
}

# [POST] Create Glossary
function createGlossary([string]$token) {
    $uri = "${catalog_endpoint}/api/atlas/v2/glossary"
    $payload = @{
        name = "Glossary"
        qualifiedName = "Glossary"
    }
    $params = @{
        ContentType = "application/json"
        Headers = @{"Authorization"=$token}
        Method = "POST"
        URI = $uri
        Body = ($payload | ConvertTo-Json -Depth 4)
    }
    $response = Invoke-RestMethod @params
    Return $response
}

# [POST] Import Glossary Terms
function importGlossaryTerms([string]$token, [string]$glossaryGuid, [string]$glossaryTermsTemplateUri) {
    $glossaryTermsFilename = "import-terms-sample.csv"
    Invoke-RestMethod -Uri $glossaryTermsTemplateUri -OutFile $glossaryTermsFilename
    $glossaryImportUri = "${catalog_endpoint}/api/atlas/v2/glossary/${glossaryGuid}/terms/import?includeTermHierarchy=true&api-version=2021-05-01-preview"
    $fieldName = 'file'
    $filePath = (Get-Item $glossaryTermsFilename).FullName
    Add-Type -AssemblyName System.Net.Http
    $client = New-Object System.Net.Http.HttpClient
    $content = New-Object System.Net.Http.MultipartFormDataContent
    $fileStream = [System.IO.File]::OpenRead($filePath)
    $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
    $content.Add($fileContent, $fieldName, $glossaryTermsFilename)
    $access_token = $token.split(" ")[1]
    $client.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $access_token)
    $result = $client.PostAsync($glossaryImportUri, $content).Result
    return $result
}

# [GET] Metadata Policy
function getMetadataPolicy([string]$token, [string]$collectionName) {
    $uri = "${pv_endpoint}/policystore/collections/${collectionName}/metadataPolicy?api-version=2021-07-01"
    $params = @{
        ContentType = "application/json"
        Headers = @{"Authorization"=$token}
        Method = "GET"
        URI = $uri
    }
    $response = Invoke-RestMethod @params
    Return $response
}

# [PUT] Metadata Policy
function putMetadataPolicy([string]$token, [string]$metadataPolicyId, [object]$payload) {
    $uri = "${pv_endpoint}/policystore/metadataPolicies/${metadataPolicyId}?api-version=2021-07-01"
    $params = @{
        ContentType = "application/json"
        Headers = @{"Authorization"=$token}
        Body = ($payload | ConvertTo-Json -Depth 10)
        Method = "PUT"
        URI = $uri
    }
    $response = Invoke-RestMethod @params
    Return $response
}

function addRoleAssignment([object]$policy, [string]$principalId, [string]$roleName) {
    Foreach ($attributeRule in $policy.properties.attributeRules) {
        if (($attributeRule.name).StartsWith("purviewmetadatarole_builtin_${roleName}:")) {
            Foreach ($conditionArray in $attributeRule.dnfCondition) {
                Foreach($condition in $conditionArray) {
                    if ($condition.attributeName -eq "principal.microsoft.id") {
                        $condition.attributeValueIncludedIn += $principalId
                    }
                 }
            }
        }
    }
}

# [PUT] Collection
function putCollection([string]$token, [string]$collectionFriendlyName, [string]$parentCollection) {
    $collectionName = -join ((97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_})
    $uri = "${pv_endpoint}/account/collections/${collectionName}?api-version=2019-11-01-preview"
    $payload = @{
        "name" = $collectionName
        "parentCollection"= @{
            "type" = "CollectionReference"
            "referenceName" = $parentCollection
        }
        "friendlyName" = $collectionFriendlyName
    }
    $params = @{
        ContentType = "application/json"
        Headers = @{"Authorization"=$token}
        Body = ($payload | ConvertTo-Json -Depth 10)
        Method = "PUT"
        URI = $uri
    }
    $response = Invoke-RestMethod @params
    Return $response
}

# 1. Get Access Token
$token = getToken $tenant_id $client_id $client_secret

# 2. Create a Key Vault Connection


# 3. Create a Credential



# 4. Update Root Collection Policy (Add Current User to Built-In Purview Roles)
$collectionName = $purview_account
$rootCollectionPolicy = getMetadataPolicy $token $collectionName
$metadataPolicyId = $rootCollectionPolicy.id
addRoleAssignment $rootCollectionPolicy $user_id "collection-administrator"
addRoleAssignment $rootCollectionPolicy $user_id "purview-reader"
addRoleAssignment $rootCollectionPolicy $user_id "data-curator"
addRoleAssignment $rootCollectionPolicy $user_id "data-source-administrator"
addRoleAssignment $rootCollectionPolicy $adf_principal_id "data-curator"
putMetadataPolicy $token $metadataPolicyId $rootCollectionPolicy

# 5. Create Collections (Sales and Marketing)


# 6. Create a Source (Azure SQL Database)


# 7. Create a Scan Configuration


# 8. Trigger Scan


# 9. Load Storage Account with Sample Data


# 10. Create a Source (ADLS Gen2)

# 11. Create a Scan Configuration

# 12. Trigger Scan


# 13. Run ADF Pipeline


# 14. Populate Glossary
