## <a name="prerequisite">Prerequisite</a> 
> A JSON API endpoint provides the team name and the corresponding API key to map a domain to a Detectify team, enabling you to access Detectify's REST API vulnerabilities endpoint and retrieve the relevant issues for each team. 


<details>  
<summary> Is the assets mapping REST API service vital? </summary>

>Yes, because Detectify lacks a central main account concept. When dealing with multiple teams, it means that each team has its own separate Detectify team. Switching between these teams is not possible through a global role. 

> Instead, each team must create a unique Detectify API key dedicated to their own team. The Detectify API key is required to access and utilize Detectify's functionalities effectively. 
 
</details>

* `The JSON API implement GET method and protected by an x-api-key. 
`

The following environment variables are required for the assets ownership JSON API:
* ```DETECTIFY_ASSETS_URL```
* ```DETECTIFY_ASSETS_API_KEY``` 

**Example:** 
> DETECTIFY_ASSETS_URL= "https://api.assetsownership.io/assets"  `// REST API endpoint url` <br>
> DETECTIFY_ASSETS_API_KEY = "MTA4NDBiMGY5Mzg5NDJmZWFmYjc" `// API Key value`

*Expected Request from detectify-check to assetsMaping service*
```
GET /assets?query=example.com HTTP/1.1
Host: api.assetsownership.io
User-Agent: vulcan-detectify-client/1.0
Content-Type: application/json
x-api-key: MTA4NDBiMGY5Mzg5NDJmZWFmYjc
```
*Expected Response (List of map) from the JSON API* 
```
[
  {
    "domainName": "example.com",
    "domainUUID": "*****",
    "teamName": "com-Team",
    "detectifyApiKey": "*****"
  },
  {
    "domainName": "io.example.com",
    "domainUUID": "****",
    "teamName": "IO-Team",
    "detectifyApiKey": "***"
  },
  {
    "domainName": "B1.example.com",
    "domainUUID": "****",
    "teamName": "B1-Team",
    "detectifyApiKey": "****"
  }
]
```
## Testing Locally 

To run the check using the ```vulcan-local``` CLI, execute the following command:
```
vulcan-local -checktypes ./vulcan-detectify/cmd -t blocket.se -a Hostname -l debug -i vulcan-detectify"
```

## Check Components 
Within this module, there are three packages:

1. `assetsOwnership` Package: This package facilitates the communication with the `DETECTIFY_ASSETS_URL` (`assetsOwnership` JSON API) in order to map domain to Detectify team and provide Detectify API key to those corresponding Detectify teams.

2. `detectify` Package: It encompasses the logic required to fetch vulnerabilities from Detectify's REST API endpoints, convert the vulnerability rows into Vulcan rows, and subsequently send them to Vulcan.

3. `utils` Package: This shared package serves the purpose of executing networking requests, generating custom errors, and logging the necessary information.








