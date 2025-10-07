package de.alexanderwolz.keycloak.docker.mapping

import org.keycloak.models.*
import org.keycloak.protocol.docker.mapper.DockerAuthV2AttributeMapper
import org.keycloak.representations.docker.DockerResponseToken
import java.util.stream.Stream

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

        //anybody with access to namespace repo is considered 'user'
        private const val ROLE_USER = "user"
        internal const val ROLE_EDITOR = "editor"
        internal const val ROLE_ADMIN = "admin"

        //can be 'user' or 'editor' or both separated by ','
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
            parseScopeIntoAccessItem(scope) ?: return responseToken //could not parse scope
        }

        if (accessItems.isEmpty()) {
            return responseToken // no action items given in scope
        }

        if (accessItems.first().actions.isEmpty()) {
            return responseToken // no actions given in scope
        }

        val clientRoleNames = getClientRoleNames(userSession.user, clientSession.client)

        return handleScopeAccess(responseToken, accessItems.first(), clientRoleNames, userSession.user)
    }

    private fun handleScopeAccess(
        responseToken: DockerResponseToken,
        accessItem: DockerScopeAccess,
        clientRoleNames: Collection<String>,
        user: UserModel,
    ): DockerResponseToken {

        //admins
        if (clientRoleNames.contains(ROLE_ADMIN)) {
            //admins can access everything
            return allowAll(responseToken, accessItem, user, "User has role '$ROLE_ADMIN'")
        }

        //users and editors
        if (accessItem.type == ACCESS_TYPE_REGISTRY) {
            return handleRegistryAccess(responseToken, clientRoleNames, accessItem, user)
        }

        if (accessItem.type == ACCESS_TYPE_REPOSITORY) {
            return handleRepositoryAccess(responseToken, clientRoleNames, accessItem, user)
        }

        if (accessItem.type == ACCESS_TYPE_REPOSITORY_PLUGIN) {
            //handle plugins the same as normal repositories
            return handleRepositoryAccess(responseToken, clientRoleNames, accessItem, user)
        }

        return deny(responseToken, accessItem, user, "Unsupported access type '${accessItem.type}'")
    }

    private fun handleRegistryAccess(
        responseToken: DockerResponseToken,
        clientRoleNames: Collection<String>,
        accessItem: DockerScopeAccess,
        user: UserModel
    ): DockerResponseToken {
        if (accessItem.name == NAME_CATALOG) {
            if (isAllowedToAccessRegistryCatalogScope(clientRoleNames)) {
                val reason = "Allowed by catalog audience '$catalogAudience'"
                return allowAll(responseToken, accessItem, user, reason)
            }
            val reason = if (clientRoleNames.contains(ROLE_EDITOR)) {
                "Role '$ROLE_ADMIN' or \$${KEY_REGISTRY_CATALOG_AUDIENCE}='$AUDIENCE_EDITOR' needed to access catalog"
            } else {
                "Role '$ROLE_ADMIN' or \$${KEY_REGISTRY_CATALOG_AUDIENCE}='$AUDIENCE_USER' needed to access catalog"
            }
            return deny(responseToken, accessItem, user, reason)
        }
        //only admins can access scope 'registry'
        val reason = "Role '$ROLE_ADMIN' needed to access registry scope"
        return deny(responseToken, accessItem, user, reason)
    }

    private fun isAllowedToAccessRegistryCatalogScope(clientRoleNames: Collection<String>): Boolean {
        return catalogAudience == AUDIENCE_USER || (catalogAudience == AUDIENCE_EDITOR && clientRoleNames.contains(
            ROLE_EDITOR
        ))
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
            //user's own repository, will have all access
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
                    val reason = "User does not belong to any namespace - check groups"
                    return deny(responseToken, accessItem, user, reason)
                }
            }
            if (namespacesFromGroups.contains(namespace)) {
                return handleNamespaceRepositoryAccess(responseToken, accessItem, clientRoleNames, user)
            }
            val reason = "Missing namespace group '$groupPrefix$namespace' - check groups"
            return deny(responseToken, accessItem, user, reason)
        }

        val reason = "User does not belong to namespace '$namespace' either by group nor username nor domain"
        return deny(responseToken, accessItem, user, reason)
    }

    internal fun getUserNamespacesFromGroups(user: UserModel): Collection<String> {
        val allSubGroups = user.groupsStream.flatMap { it.subGroupsStream }
        val allGroups = Stream.concat(user.groupsStream, allSubGroups)
        val filteredGroups = allGroups.filter { it.name.lowercase().startsWith(groupPrefix) }
        val namespaces = filteredGroups.map { it.name.lowercase().replace(groupPrefix, "") }
        return namespaces.toList()
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
            val reason = "Missing privileges for actions [${accessItem.actions.joinToString()}] - check client roles"
            return deny(responseToken, accessItem, user, reason)
        }

        if (hasAllPrivileges(allowedActions, requestedActions)) {
            val reason = "User has privilege on all actions"
            return allowWithActions(responseToken, accessItem, allowedActions, user, reason)
        }

        val reason = "User has privilege only on [${allowedActions.joinToString()}]"
        return allowWithActions(responseToken, accessItem, allowedActions, user, reason)
    }

    internal fun filterAllowedActions(
        requestedActions: Collection<String>,
        clientRoleNames: Collection<String>,
    ): List<String> {
        val allowedActions = ArrayList<String>()
        val shallAddPrivilegedActions = clientRoleNames.contains(ROLE_EDITOR) || clientRoleNames.contains(ROLE_ADMIN)
        requestedActions.forEach { action ->

            if (ACTION_PULL == action) {
                //all users in namespace group can pull images (read only by default)
                allowedActions.add(action)
            }

            if (ACTION_PUSH == action && shallAddPrivilegedActions) {
                allowedActions.add(action)
            }

            if (ACTION_DELETE == action && shallAddPrivilegedActions) {
                allowedActions.add(action)
            }

            if (ACTION_ALL == action && shallAddPrivilegedActions) {
                allowedActions.add(action)
            }

            if (ACTION_ALL == action && !shallAddPrivilegedActions && !allowedActions.contains(ACTION_PULL)) {
                //not substituted, add pull for unprivileged user (read only by default)
                allowedActions.add(ACTION_PULL)
            }
        }
        return allowedActions
    }

    private fun getCatalogAudienceFromEnv(): String {
        return getEnvVariable(KEY_REGISTRY_CATALOG_AUDIENCE)?.let {
            val audienceString = it.lowercase()
            if (audienceString == AUDIENCE_USER) {
                return@let AUDIENCE_USER
            }
            if (audienceString == AUDIENCE_EDITOR) {
                return@let AUDIENCE_EDITOR
            }
            return@let AUDIENCE_ADMIN
        } ?: AUDIENCE_ADMIN
    }

    private fun getGroupPrefixFromEnv(): String {
        return getEnvVariable(KEY_REGISTRY_GROUP_PREFIX)?.lowercase() ?: DEFAULT_REGISTRY_GROUP_PREFIX
    }

    private fun getNamespaceScopeFromEnv(): Set<String> {
        return getEnvVariable(KEY_REGISTRY_NAMESPACE_SCOPE)?.let { scopeString ->
            val scopes = scopeString.split(",").map { it.lowercase() }.filter {
                it == NAMESPACE_SCOPE_GROUP || it == NAMESPACE_SCOPE_USERNAME || it == NAMESPACE_SCOPE_DOMAIN || it == NAMESPACE_SCOPE_SLD
            }
            if (scopes.isEmpty()) {
                logger.warn{"Empty or unsupported config values for \$$KEY_REGISTRY_NAMESPACE_SCOPE: $scopeString"}
                logger.warn{"Resetting \$$KEY_REGISTRY_NAMESPACE_SCOPE to default: $NAMESPACE_SCOPE_DEFAULT"}
                NAMESPACE_SCOPE_DEFAULT
            }
            scopes.toSet()
        } ?: NAMESPACE_SCOPE_DEFAULT
    }

}