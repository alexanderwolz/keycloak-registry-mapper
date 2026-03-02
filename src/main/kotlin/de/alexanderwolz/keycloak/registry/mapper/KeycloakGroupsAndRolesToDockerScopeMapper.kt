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

        private const val ROLE_USER = "user"
        internal const val ROLE_EDITOR = "editor"
        internal const val ROLE_ADMIN = "admin"

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

        // reserved namespace names that must not be used as Keycloak group names
        internal val RESERVED_NAMESPACES = setOf(NAME_CATALOG, "default")
    }

    // will be overridden by tests
    internal var groupPrefix = getGroupPrefixFromEnv()
    internal var catalogAudience = getCatalogAudienceFromEnv()
    internal var namespaceScope = getNamespaceScopeFromEnv()

    /**
     * Represents a parsed Keycloak group path entry.
     *
     * Group path structure: /<groupPrefix><namespace>[/<repoPath>]/<role>
     *
     * Examples:
     *   /registry-company1/user              -> namespace=company1, repoPath=null,        role=user
     *   /registry-company1/editor            -> namespace=company1, repoPath=null,        role=editor
     *   /registry-company1/myrepo/editor     -> namespace=company1, repoPath=myrepo,      role=editor
     *   /registry-company1/team/myrepo/user  -> namespace=company1, repoPath=team/myrepo, role=user
     *
     * The last path segment must always be 'user' or 'editor' (the role leaf).
     * Everything between namespace and role is treated as the repo path.
     */
    internal data class GroupAccess(
        val namespace: String,
        val repoPath: String?,          // null = namespace-level, otherwise full repo path e.g. "myrepo" or "team/myrepo"
        val isEditor: Boolean,          // true = editor (pull+push+delete), false = user (pull only)
        val hasExplicitRole: Boolean    // false = plain namespace group (e.g. registry-johnny), role comes from client role
    )

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

        // admin always wins
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

        // username scope: user always has full access to their own namespace
        if (namespaceScope.contains(NAMESPACE_SCOPE_USERNAME) && isUsernameRepository(namespace, user.username)) {
            val allowedActions = substituteRequestedActions(accessItem.actions)
            return allowWithActions(responseToken, accessItem, allowedActions, user, "Accessing user's own namespace")
        }

        // domain/sld scopes: namespace matched via email, client role determines privileges
        if (namespaceScope.contains(NAMESPACE_SCOPE_DOMAIN) && isDomainRepository(namespace, user.email)) {
            val isEditor = clientRoleNames.contains(ROLE_EDITOR)
            return handleNamespaceRepositoryAccess(
                responseToken, accessItem, isEditor, user, "Namespace match via domain"
            )
        }

        if (namespaceScope.contains(NAMESPACE_SCOPE_SLD) && isSecondLevelDomainRepository(namespace, user.email)) {
            val isEditor = clientRoleNames.contains(ROLE_EDITOR)
            return handleNamespaceRepositoryAccess(
                responseToken, accessItem, isEditor, user, "Namespace match via sld"
            )
        }

        if (namespaceScope.contains(NAMESPACE_SCOPE_GROUP)) {
            return handleGroupScopeAccess(responseToken, accessItem, clientRoleNames, namespace, user)
        }

        return deny(
            responseToken, accessItem, user,
            "User does not belong to namespace '$namespace' either by group nor username nor domain"
        )
    }

    private fun handleGroupScopeAccess(
        responseToken: DockerResponseToken,
        accessItem: DockerScopeAccess,
        clientRoleNames: Collection<String>,
        namespace: String,
        user: UserModel
    ): DockerResponseToken {

        val groupAccesses = getUserGroupAccesses(user)

        if (groupAccesses.isEmpty()) {
            return deny(responseToken, accessItem, user, "User does not belong to any namespace - check groups")
        }

        val requestedRepoPath = getRepoPathFromRepositoryName(accessItem.name)

        // 1. repo-level override: check if user has explicit group for this exact repo
        if (requestedRepoPath != null) {
            val repoAccess = groupAccesses.find {
                it.namespace == namespace && it.repoPath == requestedRepoPath
            }
            if (repoAccess != null) {
                return handleNamespaceRepositoryAccess(
                    responseToken, accessItem, repoAccess.isEditor, user,
                    "Repo-level group override for '$namespace/$requestedRepoPath'"
                )
            }
        }

        // 2. namespace-level access: user has a namespace-level group (repoPath == null)
        // if group has explicit role (user/editor leaf), use that; otherwise fall back to client role
        val namespaceAccess = groupAccesses.find { it.namespace == namespace && it.repoPath == null }
        if (namespaceAccess != null) {
            val isEditor = if (namespaceAccess.hasExplicitRole) {
                namespaceAccess.isEditor
            } else {
                clientRoleNames.contains(ROLE_EDITOR)
            }
            return handleNamespaceRepositoryAccess(
                responseToken, accessItem, isEditor, user,
                "Namespace-level group match for '$namespace'"
            )
        }

        // 3. user has repo-level access in this namespace but not for this specific repo
        val hasAnyAccessInNamespace = groupAccesses.any { it.namespace == namespace }
        if (hasAnyAccessInNamespace) {
            return deny(
                responseToken, accessItem, user,
                "No matching repo-level group for '$namespace/${requestedRepoPath ?: ""}' - check groups"
            )
        }

        return deny(
            responseToken, accessItem, user,
            "Missing namespace group '$groupPrefix$namespace' - check groups"
        )
    }

    /**
     * Returns the repo path from a repository name, i.e. everything after the namespace segment.
     * Returns null if there is no repo path beyond the namespace.
     *
     * Examples:
     *   "namespace/myrepo"         -> "myrepo"
     *   "namespace/team/myrepo"    -> "team/myrepo"
     *   "image"                    -> null (no namespace)
     */
    internal fun getRepoPathFromRepositoryName(repositoryName: String): String? {
        val parts = repositoryName.split("/")
        if (parts.size < 2) return null
        return parts.drop(1).joinToString("/")
    }

    /**
     * Builds the full group path by traversing the parent chain upwards.
     * Returns a slash-separated path without a leading slash,
     * e.g. "registry-company1/myrepo/editor".
     */
    internal fun buildGroupPath(group: GroupModel): String {
        val segments = mutableListOf(group.name)
        var parent = group.parent
        while (parent != null) {
            segments.add(0, parent.name)
            parent = parent.parent
        }
        return segments.joinToString("/")
    }

    /**
     * Parses all Keycloak group memberships of a user into [GroupAccess] objects.
     *
     * Note: user.groupsStream returns ALL groups the user is directly a member of,
     * including nested subgroups - Keycloak flattens this automatically.
     * Groups that do not match the expected structure are silently ignored.
     */
    internal fun getUserGroupAccesses(user: UserModel): List<GroupAccess> {
        return user.groupsStream.toList().mapNotNull { group ->
            parseGroupPath(buildGroupPath(group))
        }
    }

    /**
     * Parses a Keycloak group path into a [GroupAccess] object.
     *
     * Path format: /<groupPrefix><namespace>[/<repoSegments...>]/<role>
     *
     * The last segment must be 'user' or 'editor'.
     * Returns null if the path does not match the expected structure.
     */
    internal fun parseGroupPath(path: String): GroupAccess? {
        // Keycloak paths always start with /, e.g. /registry-company1/myrepo/editor
        val normalizedPath = path.lowercase().trimStart('/')
        val segments = normalizedPath.split("/")

        // first segment must start with groupPrefix
        val firstSegment = segments[0]
        if (!firstSegment.startsWith(groupPrefix)) return null

        // extract namespace (everything after the prefix in the first segment)
        val namespace = firstSegment.removePrefix(groupPrefix)
        if (namespace.isEmpty()) return null

        // plain namespace group e.g. registry-johnny (no role leaf)
        // role is determined by client role, not group
        if (segments.size == 1) {
            return GroupAccess(namespace, repoPath = null, isEditor = false, hasExplicitRole = false)
        }

        // last segment must be the role leaf
        val roleLeaf = segments.last()
        val isEditor = when (roleLeaf) {
            ROLE_EDITOR -> true
            ROLE_USER -> false
            else -> return null // not a valid role leaf, ignore this group
        }

        // everything between namespace segment and role leaf is the repo path
        val repoSegments = segments.drop(1).dropLast(1)
        val repoPath = if (repoSegments.isEmpty()) null else repoSegments.joinToString("/")

        return GroupAccess(namespace, repoPath, isEditor, hasExplicitRole = true)
    }

    private fun handleNamespaceRepositoryAccess(
        responseToken: DockerResponseToken,
        accessItem: DockerScopeAccess,
        isEditor: Boolean,
        user: UserModel,
        context: String
    ): DockerResponseToken {

        val requestedActions = substituteRequestedActions(accessItem.actions)
        val allowedActions = filterAllowedActions(requestedActions, isEditor)

        if (allowedActions.isEmpty()) {
            return deny(
                responseToken, accessItem, user,
                "Missing privileges for actions [${accessItem.actions.joinToString()}] - $context"
            )
        }

        val reason = if (hasAllPrivileges(allowedActions, requestedActions)) {
            "User has privilege on all actions ($context)"
        } else {
            "User has privilege only on [${allowedActions.joinToString()}] ($context)"
        }
        return allowWithActions(responseToken, accessItem, allowedActions, user, reason)
    }

    /**
     * Filters the requested actions based on whether the user is an editor or just a user.
     * Editor: pull, push, delete, *
     * User: pull only
     */
    internal fun filterAllowedActions(
        requestedActions: Collection<String>,
        isEditor: Boolean
    ): List<String> {
        return requestedActions.flatMap { action ->
            when (action) {
                ACTION_PULL -> listOf(ACTION_PULL)
                ACTION_PUSH -> if (isEditor) listOf(ACTION_PUSH) else emptyList()
                ACTION_DELETE -> if (isEditor) listOf(ACTION_DELETE) else emptyList()
                ACTION_ALL -> if (isEditor) listOf(ACTION_ALL) else listOf(ACTION_PULL)
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
