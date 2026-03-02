package de.alexanderwolz.keycloak.registry.mapper

import org.keycloak.models.*
import org.keycloak.protocol.docker.mapper.DockerAuthV2AttributeMapper
import org.keycloak.representations.docker.DockerResponseToken

// reference: https://www.baeldung.com/keycloak-custom-protocol-mapper
// see also https://www.keycloak.org/docs-api/21.1.1/javadocs/org/keycloak/protocol/ProtocolMapper.html
// see also https://www.keycloak.org/docs-api/21.1.1/javadocs/org/keycloak/protocol/docker/mapper/DockerAuthV2ProtocolMapper.html
// see also https://docs.docker.com/registry/spec/auth/token/

class KeycloakGroupsAndRolesToDockerScopeMapper : AbstractDockerScopeMapper(
    "docker-v2-allow-by-groups-and-roles-mapper",
    "Allow by Groups and Roles",
    "Maps Docker v2 scopes by user roles and groups"
), DockerAuthV2AttributeMapper {

    companion object {

        internal const val KEY_REGISTRY_GROUP_PREFIX = "REGISTRY_GROUP_PREFIX"
        internal const val DEFAULT_REGISTRY_GROUP_PREFIX = "registry-"

        // anybody with access to namespace repo is considered 'user'
        private const val ROLE_USER = "user"
        internal const val ROLE_EDITOR = "editor"
        internal const val ROLE_ADMIN = "admin"

        // can be 'user' or 'editor' or both separated by ','
        internal const val KEY_REGISTRY_CATALOG_AUDIENCE = "REGISTRY_CATALOG_AUDIENCE"
        internal const val AUDIENCE_USER = ROLE_USER
        internal const val AUDIENCE_EDITOR = ROLE_EDITOR
        internal const val AUDIENCE_ADMIN = ROLE_ADMIN

        internal const val KEY_REGISTRY_NAMESPACE_SCOPE = "REGISTRY_NAMESPACE_SCOPE"
        internal const val NAMESPACE_SCOPE_USERNAME = "username"
        internal const val NAMESPACE_SCOPE_GROUP = "group"
        internal const val NAMESPACE_SCOPE_DOMAIN = "domain"
        internal const val NAMESPACE_SCOPE_SLD = "sld"
        internal val NAMESPACE_SCOPE_DEFAULT = setOf(NAMESPACE_SCOPE_GROUP)
    }

    // will be overridden by tests
    internal var groupPrefix = getGroupPrefixFromEnv()
    internal var catalogAudience = getCatalogAudienceFromEnv()
    internal var namespaceScope = getNamespaceScopeFromEnv()

    override fun appliesTo(responseToken: DockerResponseToken?): Boolean {
        return true
    }

    override fun transformDockerResponseToken(
        responseToken: DockerResponseToken,
        mappingModel: ProtocolMapperModel,
        session: KeycloakSession,
        userSession: UserSessionModel,
        clientSession: AuthenticatedClientSessionModel
    ): DockerResponseToken {

        val accessItems = getScopesFromSession(clientSession).map { scope ->
            parseScopeIntoAccessItem(scope) ?: return responseToken
        }

        if (accessItems.isEmpty()) {
            return responseToken
        }

        if (accessItems.first().actions.isEmpty()) {
            return responseToken
        }

        val clientRoleNames = getClientRoleNames(userSession.user, clientSession.client)

        // NOTE: Only the first access item is processed intentionally.
        // Docker clients typically send one scope per token request.
        // Multi-scope requests are not yet supported and will silently ignore additional scopes.
        return handleScopeAccess(responseToken, accessItems.first(), clientRoleNames, userSession.user)
    }

    private fun handleScopeAccess(
        responseToken: DockerResponseToken,
        accessItem: DockerScopeAccess,
        clientRoleNames: Collection<String>,
        user: UserModel,
    ): DockerResponseToken {

        if (clientRoleNames.contains(ROLE_ADMIN)) {
            return allowAll(responseToken, accessItem, user, "User has role '$ROLE_ADMIN'")
        }

        return when (accessItem.type) {
            ACCESS_TYPE_REGISTRY -> handleRegistryAccess(responseToken, clientRoleNames, accessItem, user)
            ACCESS_TYPE_REPOSITORY -> handleRepositoryAccess(responseToken, clientRoleNames, accessItem, user)
            // plugins are handled the same as normal repositories
            ACCESS_TYPE_REPOSITORY_PLUGIN -> handleRepositoryAccess(responseToken, clientRoleNames, accessItem, user)
            else -> deny(responseToken, accessItem, user, "Unsupported access type '${accessItem.type}'")
        }
    }

    private fun handleRegistryAccess(
        responseToken: DockerResponseToken,
        clientRoleNames: Collection<String>,
        accessItem: DockerScopeAccess,
        user: UserModel
    ): DockerResponseToken {
        if (accessItem.name == NAME_CATALOG) {
            if (isAllowedToAccessRegistryCatalogScope(clientRoleNames)) {
                return allowAll(responseToken, accessItem, user, "Allowed by catalog audience '$catalogAudience'")
            }
            val reason = if (clientRoleNames.contains(ROLE_EDITOR)) {
                "Role '$ROLE_ADMIN' or \$${KEY_REGISTRY_CATALOG_AUDIENCE}='$AUDIENCE_EDITOR' needed to access catalog"
            } else {
                "Role '$ROLE_ADMIN' or \$${KEY_REGISTRY_CATALOG_AUDIENCE}='$AUDIENCE_USER' needed to access catalog"
            }
            return deny(responseToken, accessItem, user, reason)
        }
        return deny(responseToken, accessItem, user, "Role '$ROLE_ADMIN' needed to access registry scope")
    }

    private fun isAllowedToAccessRegistryCatalogScope(clientRoleNames: Collection<String>): Boolean {
        return catalogAudience == AUDIENCE_USER ||
                (catalogAudience == AUDIENCE_EDITOR && clientRoleNames.contains(ROLE_EDITOR))
    }

    private fun handleRepositoryAccess(
        responseToken: DockerResponseToken,
        clientRoleNames: Collection<String>,
        accessItem: DockerScopeAccess,
        user: UserModel
    ): DockerResponseToken {

        val namespace = getNamespaceFromRepositoryName(accessItem.name) ?: return deny(
            responseToken, accessItem, user, "Role '$ROLE_ADMIN' needed to access default namespace repositories"
        )

        if (namespaceScope.contains(NAMESPACE_SCOPE_USERNAME) && isUsernameRepository(namespace, user.username)) {
            val allowedActions = substituteRequestedActions(accessItem.actions)
            return allowWithActions(responseToken, accessItem, allowedActions, user, "Accessing user's own namespace")
        }

        if (namespaceScope.contains(NAMESPACE_SCOPE_DOMAIN) && isDomainRepository(namespace, user.email)) {
            return handleNamespaceRepositoryAccess(responseToken, accessItem, clientRoleNames, user)
        }

        if (namespaceScope.contains(NAMESPACE_SCOPE_SLD) && isSecondLevelDomainRepository(namespace, user.email)) {
            return handleNamespaceRepositoryAccess(responseToken, accessItem, clientRoleNames, user)
        }

        if (namespaceScope.contains(NAMESPACE_SCOPE_GROUP)) {
            val namespacesFromGroups = getUserNamespacesFromGroups(user).also {
                if (it.isEmpty()) {
                    return deny(responseToken, accessItem, user, "User does not belong to any namespace - check groups")
                }
            }
            if (namespacesFromGroups.contains(namespace)) {
                return handleNamespaceRepositoryAccess(responseToken, accessItem, clientRoleNames, user)
            }
            return deny(
                responseToken,
                accessItem,
                user,
                "Missing namespace group '$groupPrefix$namespace' - check groups"
            )
        }

        return deny(
            responseToken, accessItem, user,
            "User does not belong to namespace '$namespace' either by group nor username nor domain"
        )
    }

    internal fun getUserNamespacesFromGroups(user: UserModel): Collection<String> {
        val topLevelGroups = user.groupsStream.toList()
        val allSubGroups = topLevelGroups.flatMap { it.subGroupsStream.toList() }
        val allGroups = topLevelGroups + allSubGroups
        return allGroups
            .filter { it.name.lowercase().startsWith(groupPrefix) }
            .map { it.name.lowercase().replace(groupPrefix, "") }
    }

    private fun handleNamespaceRepositoryAccess(
        responseToken: DockerResponseToken,
        accessItem: DockerScopeAccess,
        clientRoleNames: Collection<String>,
        user: UserModel
    ): DockerResponseToken {

        val requestedActions = substituteRequestedActions(accessItem.actions)
        val allowedActions = filterAllowedActions(requestedActions, clientRoleNames)

        if (allowedActions.isEmpty()) {
            return deny(
                responseToken, accessItem, user,
                "Missing privileges for actions [${accessItem.actions.joinToString()}] - check client roles"
            )
        }

        val reason = if (hasAllPrivileges(allowedActions, requestedActions)) {
            "User has privilege on all actions"
        } else {
            "User has privilege only on [${allowedActions.joinToString()}]"
        }
        return allowWithActions(responseToken, accessItem, allowedActions, user, reason)
    }

    internal fun filterAllowedActions(
        requestedActions: Collection<String>,
        clientRoleNames: Collection<String>,
    ): List<String> {
        val isPrivileged = clientRoleNames.contains(ROLE_EDITOR) || clientRoleNames.contains(ROLE_ADMIN)
        return requestedActions.flatMap { action ->
            when (action) {
                ACTION_PULL -> listOf(ACTION_PULL)
                ACTION_PUSH -> if (isPrivileged) listOf(ACTION_PUSH) else emptyList()
                ACTION_DELETE -> if (isPrivileged) listOf(ACTION_DELETE) else emptyList()
                ACTION_ALL -> if (isPrivileged) listOf(ACTION_ALL) else listOf(ACTION_PULL)
                else -> emptyList()
            }
        }.distinct()
    }

    private fun getCatalogAudienceFromEnv(): String {
        return when (getEnvVariable(KEY_REGISTRY_CATALOG_AUDIENCE)?.lowercase()) {
            AUDIENCE_USER -> AUDIENCE_USER
            AUDIENCE_EDITOR -> AUDIENCE_EDITOR
            else -> AUDIENCE_ADMIN
        }
    }

    private fun getGroupPrefixFromEnv(): String {
        return getEnvVariable(KEY_REGISTRY_GROUP_PREFIX)?.lowercase() ?: DEFAULT_REGISTRY_GROUP_PREFIX
    }

    private fun getNamespaceScopeFromEnv(): Set<String> {
        val scopeString = getEnvVariable(KEY_REGISTRY_NAMESPACE_SCOPE) ?: return NAMESPACE_SCOPE_DEFAULT
        val validScopes =
            setOf(NAMESPACE_SCOPE_GROUP, NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_DOMAIN, NAMESPACE_SCOPE_SLD)
        val scopes = scopeString.split(",").map { it.lowercase() }.filter { it in validScopes }.toSet()

        if (scopes.isEmpty()) {
            logger.warn { "Empty or unsupported config values for \$$KEY_REGISTRY_NAMESPACE_SCOPE: $scopeString" }
            logger.warn { "Resetting \$$KEY_REGISTRY_NAMESPACE_SCOPE to default: $NAMESPACE_SCOPE_DEFAULT" }
            return NAMESPACE_SCOPE_DEFAULT
        }
        return scopes
    }
}