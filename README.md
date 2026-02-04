# Docker v2 - Groups and Role Mapper for Keycloak 26.x

![GitHub release (latest by date)](https://img.shields.io/github/v/release/alexanderwolz/keycloak-registry-mapper)
![GitHub](https://img.shields.io/badge/keycloak-26.4.0-orange)
![GitHub](https://img.shields.io/badge/registry-2.8.2-orange)
![GitHub](https://img.shields.io/github/license/alexanderwolz/keycloak-registry-mapper)
![GitHub](https://img.shields.io/badge/test_cases-657-informational)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/alexanderwolz/keycloak-registry-mapper)
![GitHub all releases](https://img.shields.io/github/downloads/alexanderwolz/keycloak-registry-mapper/total?color=informational)

## 🧑‍💻 About

This repository provides a MappingProvider for Keycloak's Docker-v2 protocol. It manages registry access for users with client role ```admin``` or ```editor``` and who are assigned to realm groups named like ```registry-${namespace}```. Clients without any roles are treated as ```user``` and will be granted read-only access to the namespace by default. This behavior can be overwritten by environment variables (see configuration) 

## 🛠️ Build
1. Create jar resource using ```./gradlew clean build```
2. Copy  ```/build/libs/*.jar``` into Keycloak´s ```/opt/keycloak/providers/``` folder
3. Build keycloak instance using ```/opt/keycloak/bin/kc.sh build```

See also Keycloak [Dockerfile](https://github.com/alexanderwolz/keycloak-registry-mapper/blob/main/examples/keycloak-with-mapper/Dockerfile) for reference in [examples](https://github.com/alexanderwolz/keycloak-registry-mapper/tree/main/examples) section.

## 🐳 Docker Image
Alternatively use a pre-built Keycloak Docker [image](https://hub.docker.com/r/alexanderwolz/keycloak), which bundles this mapper plugin.

## 🔬 Basic Concept
- Users can be grouped to the same repository namespace by assigning them to one or several groups starting with ```registry-```.
- Without any client roles assigned, users will be granted read-only access to their namespaces.
- Default namespaces (repositories without prefix/) can only be accessed by admins.
- Assigning the client role ```editor``` will allow users to also push and delete images in their namespaces.
- Assigning the client role ```admin``` will allow access to any resource in the whole registry and give full access.
- Users could be grouped to domain-namespaces according to their email-addresses  (can be configured via environment variables, default off)
- Without having any roles and groups assigned, users will have full access to the namespace if it matches their username (can be configured via environment variables, default off)
- **Role attributes** can be used to grant per-namespace permissions without requiring group membership (see below)

## ⚙️ Configuration
This mapper supports following environment variables (either set on server or in docker container):

| Variable Name                   | Values                                               | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|---------------------------------|------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ```REGISTRY_CATALOG_AUDIENCE``` | ```editor```, ```user```                             | Will allow editors or users to access *registry:catalog:** scope. That would be of interest to users who want to access UI frontends.<br> No scope is set by default, so only admins are allowed to access registry scope.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ```REGISTRY_NAMESPACE_SCOPE```  | ```group```, ```domain```, ```sld```, ```username``` | If ```group``` is set, users are checked for group membership and will be granted access to the repository according to their roles.<br>If ```domain``` is set, users are checked against their email domain and will be granted access to the repository (e.g. *company.com/image*) according to their roles.<br>If ```sld``` is set, users are checked against their email second level domain (sld) and will be granted access to the repository (e.g. *company/image*) according to their roles.<br>If ```username``` is set, users will be granted full access to the namespace if it matches their username (lowercase check).<br><br>Namespace scope ```group``` is set by default or if value is empty or no value matches ```group```, ```domain```, ```sld``` or ```username``` (all values can be concatenated with ```,```). |
| ```REGISTRY_GROUP_PREFIX```     | any String                                           | Custom group prefix. Will default to ```registry-```. Comparisons will be checked with lowercase String representation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |


## 🔒 Keycloak Setup

Keycloak must be setup to have a docker-v2 registry client, roles and optional groups. The registry then must be configured to use OIDC configuration provided by Keycloak

### Enable Docker v2 Protocol Feature
1. In order to use the Docker v2 protocol, the feature ```docker``` must be enabled during Keycloak server startup.
2. This can be done by setting the environment variable ```KC_FEATURES=docker,token-exchange```.

### Create Registry Client Configuration
1. Go to realm and choose "Clients" section
2. Create new client by clicking "Create client"
3. Choose Client Type *docker-v2* and insert client id e.g. "myregistry"
4. Set valid redirect URL

### Create Client Roles
1. In Client Page, choose "Roles"-tab
2. Click "Create role" and set role name to ```admin```
3. Go back to "Roles"-tab
4. Click "Create role" and set role name to ```editor```

### Set the Mapper
1. in Client Page, choose "Client scopes"-tab
2. Go to "myregistry-dedicated" scope
3. Delete "docker-v2-allow-all-mapper" configuration
4. Click "Configure a new mapper" button
5. Choose "Allow by Groups and Roles" mapper (this mapper)
6. Give it a name e.g. "Allow by Groups and Roles Mapper"

![Keycloak Registry Client Config](assets/keycloak-config/create_registry_client.gif)

### Create Roles
1. Go to realm and choose "Groups" section
2. Click "Create group"
3. Name it "registry-mycompany"

### Assign Roles to users
1. Go to realm and choose "Users" section
2. Choose your user and select "Role mapping"
3. Click "Assign role"
4. Filter by "clients" and search for 'myregistry'
5. Choose either ```admin``` or ```editor```
6. Click "Assign"

### Assign Groups to users
1. Go to realm and choose "Users" section
2. Choose your user and select "Groups"
3. Click "Join Group"
4. Select "registry-mycompany"
5. Click "Join"
6. Now the user will have access to registry namespace *myregistry.com/mycompany/*

![Keycloak Registry Client Config](assets/keycloak-config/assign_role_and_group_to_user.gif)

## 🎯 Per-Namespace Permissions with Role Attributes

Role attributes allow you to define fine-grained, per-namespace permissions directly on client roles. This is useful when users need different permission levels for different namespaces.

### Role Attribute Format

Add attributes to any client role using the format:
- **Key:** ```registry:{namespace}```
- **Value:** ```pull```, ```push```, ```delete```, or ```*``` (comma-separated for multiple actions)

| Attribute Key | Attribute Value | Result |
|---------------|-----------------|--------|
| ```registry:myrepo``` | ```pull``` | Pull-only access to myrepo namespace |
| ```registry:myrepo``` | ```pull,push``` | Pull and push access to myrepo namespace |
| ```registry:myrepo``` | ```pull,push,delete``` | Full access to myrepo namespace |
| ```registry:myrepo``` | ```*``` | Full access (expands to pull,push,delete) |
| ```registry``` | ```catalog``` | Grants catalog access regardless of REGISTRY_CATALOG_AUDIENCE |

### How Role Attributes Combine with Groups

| Access Method | Permissions |
|---------------|-------------|
| Group membership only | pull (read-only by default) |
| Group + ```editor``` role | pull, push, delete |
| Group + role attribute | Group permissions + attribute permissions (combined) |
| Role attribute only (no group) | Exactly what's specified in the attribute |

### Setup Role Attributes in Keycloak

1. Go to your realm and choose "Clients" section
2. Select your registry client (e.g., "myregistry")
3. Go to "Roles" tab
4. Create a new role or select an existing one
5. Go to the "Attributes" tab
6. Add attributes with key ```registry:{namespace}``` and value as the allowed actions

### Example Use Cases

**Use Case 1: User needs push access to one specific namespace**

User is member of groups ```registry-repository-1``` and ```registry-repository-2``` (pull-only by default).
User needs push access to ```repository-1``` but not ```repository-2```.

Solution: Create a role with attribute:
- Key: ```registry:repository-1```
- Value: ```push```

Result: User gets pull from both repos (via groups), plus push to repository-1 (via attribute).

**Use Case 2: User needs access to a namespace without group membership**

User needs pull,push access to ```repository-3``` but should not be added to any group.

Solution: Create a role with attribute:
- Key: ```registry:repository-3```
- Value: ```pull,push```

Result: User gets pull,push access to repository-3 directly via the role attribute.

**Use Case 3: Create a project role that bundles multiple namespace permissions**

Create a role "project-alpha" with multiple attributes:
- ```registry:project-frontend``` = ```pull,push,delete```
- ```registry:project-backend``` = ```pull,push,delete```
- ```registry:shared-libs``` = ```pull```

Result: Assign this single role to grant access to all project namespaces with appropriate permissions.

**Use Case 4: Grant catalog access to specific users without changing global settings**

By default, ```REGISTRY_CATALOG_AUDIENCE``` is set to ```admin```, meaning only admins can list repositories.
To grant catalog access to specific users or roles without changing the global setting:

Solution: Create a role with attribute:
- Key: ```registry```
- Value: ```catalog```

Result: Users with this role can access the registry catalog (list repositories), while other non-admin users remain restricted.

- - -

Made with ❤️ in Bavaria
<br>
© 2025, <a href="https://www.alexanderwolz.de"> Alexander Wolz
