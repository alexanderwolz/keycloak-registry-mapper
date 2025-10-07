package de.alexanderwolz.keycloak.docker.mapping

import de.alexanderwolz.commons.log.Logger
import org.keycloak.models.AuthenticatedClientSessionModel
import org.keycloak.models.ClientModel
import org.keycloak.models.UserModel
import org.keycloak.protocol.docker.DockerAuthV2Protocol
import org.keycloak.protocol.docker.mapper.DockerAuthV2ProtocolMapper
import org.keycloak.representations.docker.DockerAccess
import org.keycloak.representations.docker.DockerResponseToken

abstract class AbstractDockerScopeMapper(
    private val id: String,
    private val displayType: String,
    private val helpText: String
) : DockerAuthV2ProtocolMapper() {

    companion object {
        const val NAME_CATALOG = "catalog"

        const val ACTION_PULL = "pull"
        const val ACTION_PUSH = "push"
        const val ACTION_DELETE = "delete"
        const val ACTION_ALL = "*"
        val ACTION_ALL_SUBSTITUTE = listOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)

        //see also https://docs.docker.com/registry/spec/auth/scope/
        const val ACCESS_TYPE_REGISTRY = "registry"
        const val ACCESS_TYPE_REPOSITORY = "repository"
        const val ACCESS_TYPE_REPOSITORY_PLUGIN = "repository(plugin)"

    }

    internal val logger = Logger(javaClass)

    override fun getId(): String {
        return id
    }

    override fun getDisplayType(): String {
        return displayType
    }

    override fun getHelpText(): String {
        return helpText
    }

    internal fun getScopesFromSession(clientSession: AuthenticatedClientSessionModel): Collection<String> {
        val scopeString = clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)
        if (logger.isDebugEnabled && (scopeString == null || scopeString.isEmpty())) {
            logger.debug{"Session does not contain a scope, ignoring further access check"}
        }
        return scopeString?.split(" ") ?: emptySet()
    }

    internal fun parseScopeIntoAccessItem(scope: String): DockerScopeAccess? {
        return try {
            val accessItem = DockerScopeAccess(scope)
            logger.trace{"Parsed scope '$scope' into: $accessItem"}
            accessItem
        } catch (e: Exception) {
            logger.warn{"Could not parse scope '$scope' into access object: ${e.message}"}
            null
        }
    }

    internal fun getClientRoleNames(user: UserModel, client: ClientModel): Collection<String> {
        return user.getClientRoleMappingsStream(client).map { it.name }.toList()
    }

    internal fun getDomainFromEmail(email: String): String? {
        val parts = email.split("@")
        if (parts.size == 2) {
            val domain = parts.last()
            if (domain.isNotEmpty()) {
                return domain
            }
        }
        return null //no valid domain
    }

    internal fun getSecondLevelDomainFromEmail(email: String): String? {
        val domain = getDomainFromEmail(email) ?: return null
        val parts = domain.split(".")
        if (parts.size > 1) {
            val sld = parts[parts.size - 2]
            if (sld.isNotEmpty()) {
                return sld
            }
        }
        return null
    }

    internal fun isUsernameRepository(namespace: String, username: String): Boolean {
        return namespace == username.lowercase()
    }

    internal fun isDomainRepository(namespace: String, email: String): Boolean {
        return namespace == getDomainFromEmail(email)
    }

    internal fun isSecondLevelDomainRepository(namespace: String, email: String): Boolean {
        return namespace == getSecondLevelDomainFromEmail(email)
    }

    internal fun hasAllPrivileges(actions: Collection<String>, requestedActions: Collection<String>): Boolean {
        return isSubstituteWithActionAll(actions, requestedActions) || actions.containsAll(requestedActions)
    }

    internal fun isSubstituteWithActionAll(
        actions: Collection<String>, requestedActions: Collection<String>
    ): Boolean {
        return requestedActions.size == 1 && requestedActions.first() == ACTION_ALL && actions.containsAll(
            ACTION_ALL_SUBSTITUTE
        )
    }

    internal fun getNamespaceFromRepositoryName(repositoryName: String): String? {
        //namespace can be followed of sub-namespaces (segments) divided by / (slash)
        val parts = repositoryName.split("/")
        if (parts.size > 1) {
            return parts[0].lowercase()
        }
        return null
    }

    internal fun substituteRequestedActions(requestedActions: Collection<String>): List<String> {
        // replaces '*' by pull, push and delete
        return HashSet(requestedActions).also { actions ->
            if (actions.contains(ACTION_ALL)) {
                actions.remove(ACTION_ALL)
                actions.addAll(ACTION_ALL_SUBSTITUTE)
            }
        }.toList()
    }

    internal fun allowAll(
        responseToken: DockerResponseToken,
        accessItem: DockerScopeAccess,
        user: UserModel,
        reason: String
    ): DockerResponseToken {
        logger.debug{"Granting access for user '${user.username}' on scope '${accessItem.scope}': $reason"}

        responseToken.accessItems.add(accessItem)
        return responseToken
    }

    internal fun allowWithActions(
        responseToken: DockerResponseToken,
        accessItem: DockerScopeAccess,
        allowedActions: List<String>,
        user: UserModel,
        reason: String
    ): DockerResponseToken {
        logger.debug{"Granting access for user '${user.username}' on scope '${accessItem.scope}': $reason"}
        accessItem.actions = allowedActions
        responseToken.accessItems.add(accessItem)
        return responseToken
    }

    internal fun deny(
        responseToken: DockerResponseToken,
        accessItem: DockerScopeAccess,
        user: UserModel,
        reason: String
    ): DockerResponseToken {
        logger.warn{"Access denied for user '${user.username}' on scope '${accessItem.scope}': $reason"}
        return responseToken
    }

    internal fun getEnvVariable(key: String): String? {
        return try {
            System.getenv()[key]
        } catch (e: Exception) {
            logger.error(e) { "Could not access System Environment" }
            null
        }
    }

    // cache plain scope into DockerAccess class
    internal class DockerScopeAccess(val scope: String) : DockerAccess(scope)

}