package de.alexanderwolz.keycloak.registry.mapper

import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_ALL
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_ALL_SUBSTITUTE
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_DELETE
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_PULL
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_PUSH
import org.junit.jupiter.api.Test
import org.keycloak.models.AuthenticatedClientSessionModel
import org.keycloak.models.ClientModel
import org.keycloak.models.RoleContainerModel
import org.keycloak.models.RoleModel
import org.keycloak.models.UserModel
import org.keycloak.protocol.docker.DockerAuthV2Protocol
import org.keycloak.representations.docker.DockerResponseToken
import org.mockito.Mockito
import org.mockito.kotlin.given
import kotlin.test.*

internal class AbstractDockerScopeMapperTest {

    private val mapper = object : AbstractDockerScopeMapper("id", "type", "text") {}

    @Test
    fun testGetLogger() {
        assertNotNull(mapper.logger)
    }

    @Test
    fun testGetRegistryCatalogScopeFromSession() {
        val expectedScope = "registry:catalog:*"
        val clientSession = Mockito.mock(AuthenticatedClientSessionModel::class.java)
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        val scopes = mapper.getScopesFromSession(clientSession)
        assertEquals(1, scopes.size)
        assertEquals(expectedScope, scopes.first())
    }

    @Test
    fun testGetRepositoryScopeFromSession() {
        val expectedScope = "repository:image:pull,push,delete"
        val clientSession = Mockito.mock(AuthenticatedClientSessionModel::class.java)
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        val scopes = mapper.getScopesFromSession(clientSession)
        assertEquals(1, scopes.size)
        assertEquals(expectedScope, scopes.first())
    }
    @Test
    fun testGetRepositoryScopeWithNamespaceFromSession() {
        val expectedScope = "repository:john/image:pull,push,delete"
        val clientSession = Mockito.mock(AuthenticatedClientSessionModel::class.java)
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        val scopes = mapper.getScopesFromSession(clientSession)
        assertEquals(1, scopes.size)
        assertEquals(expectedScope, scopes.first())
    }

    @Test
    fun testGetScopeFromSessionWithTwoScopes() {
        val expectedScopes = setOf("registry:catalog:*", "repository:image:pull")
        val scopeString = expectedScopes.joinToString(" ")
        val clientSession = Mockito.mock(AuthenticatedClientSessionModel::class.java)
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(scopeString)
        val scopes = mapper.getScopesFromSession(clientSession)
        assertEquals(2, scopes.size)
        assertEquals(expectedScopes.sorted(), scopes.sorted())
    }

    @Test
    fun testGetScopeFromSessionWithNull() {
        val clientSession = Mockito.mock(AuthenticatedClientSessionModel::class.java)
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(null)
        val scopes = mapper.getScopesFromSession(clientSession)
        assertEquals(0, scopes.size)
    }

    @Test
    fun testParseScopeIntoAccessItem() {
        val accessItem = mapper.parseScopeIntoAccessItem("registry:catalog:*")
        assertNotNull(accessItem)
        assertEquals("registry", accessItem.type)
        assertEquals("catalog", accessItem.name)
        assertEquals(1, accessItem.actions.size)
        assertEquals("*", accessItem.actions.first())
    }

    @Test
    fun testParseScopeIntoAccessItemWithWrongSyntax() {
        val accessItem = mapper.parseScopeIntoAccessItem("registry:catalog*")
        assertNull(accessItem)
    }

    @Test
    fun testGetClientRoleNames() {
        val client = Mockito.mock(ClientModel::class.java)
        given(client.id).willReturn("client-id")

        val user = Mockito.mock(UserModel::class.java)
        val expectedRoleNames = listOf("editor", "otherRoleWithCamelCase")

        val roles = expectedRoleNames.map { roleName ->
            val role = Mockito.mock(RoleModel::class.java)
            val container = Mockito.mock(ClientModel::class.java)
            given(container.id).willReturn("client-id")
            given(role.name).willReturn(roleName)
            given(role.container).willReturn(container)
            role
        }

        given(user.roleMappingsStream).willReturn(roles.stream())

        val roleNames = mapper.getClientRoleNames(user, client)
        assertEquals(expectedRoleNames.sorted(), roleNames.sorted())
    }

    @Test
    fun testGetDomainFromEmailW() {
        val domain = mapper.getDomainFromEmail("john.doe@company.com")
        assertEquals("company.com", domain)
    }

    @Test
    fun testGetDomainFromEmailWithWrongString() {
        val domain = mapper.getDomainFromEmail("john.doe@")
        assertNull(domain)
    }

    @Test
    fun testGetSecondLevelDomainFromEmail() {
        val sld = mapper.getSecondLevelDomainFromEmail("john.doe@company.com")
        assertEquals("company", sld)
    }

    @Test
    fun testGetSecondLevelDomainFromEmailWithSubdomain() {
        val sld = mapper.getSecondLevelDomainFromEmail("john.doe@mail.company.com")
        assertEquals("company", sld)
    }

    @Test
    fun testGetSecondLevelDomainFromEmailWithInvalidEmail() {
        val sld = mapper.getSecondLevelDomainFromEmail("john.doe")
        assertNull(sld)
    }

    @Test
    fun testIsUsernameRepository() {
        assertTrue(mapper.isUsernameRepository("username", "username"))
    }

    @Test
    fun testIsUsernameRepositoryDifferentValues() {
        assertFalse(mapper.isUsernameRepository("username", "johnny"))
    }

    @Test
    fun testIsUsernameRepositoryWithCamelCase() {
        assertTrue(mapper.isUsernameRepository("username", "userName"))
    }

    @Test
    fun testIsDomainRepository() {
        assertTrue(mapper.isDomainRepository("company.com", "johnny@company.com"))
    }

    @Test
    fun testIsDomainRepositoryWithOtherEmail() {
        assertFalse(mapper.isDomainRepository("company.com", "johnny@company.net"))
    }

    @Test
    fun testIsSecondLevelDomainRepository() {
        assertTrue(mapper.isSecondLevelDomainRepository("company", "johnny@company.com"))
    }

    @Test
    fun testIsSecondLevelDomainRepositoryWithOtherTld() {
        assertTrue(mapper.isSecondLevelDomainRepository("company", "johnny@company.net"))
    }

    @Test
    fun testIsSecondLevelDomainRepositoryWithOtherEmail() {
        assertFalse(mapper.isSecondLevelDomainRepository("company", "johnny@example.org"))
    }

    @Test
    fun testHasAllPrivileges() {
        val requestedActions = setOf(ACTION_PULL, ACTION_DELETE)
        val actions = setOf(ACTION_DELETE, ACTION_PULL)
        val hasAllPrivileges = mapper.hasAllPrivileges(actions, requestedActions)
        assertTrue(hasAllPrivileges)
    }

    @Test
    fun testHasAllPrivilegesWithSubstitute() {
        val requestedActions = setOf(ACTION_ALL)
        val actions = ACTION_ALL_SUBSTITUTE
        val hasAllPrivileges = mapper.hasAllPrivileges(actions, requestedActions)
        assertTrue(hasAllPrivileges)
    }

    @Test
    fun testHasAllPrivilegesFails() {
        val requestedActions = setOf(ACTION_PUSH)
        val actions = setOf(ACTION_PULL)
        val hasAllPrivileges = mapper.hasAllPrivileges(actions, requestedActions)
        assertFalse(hasAllPrivileges)
    }


    @Test
    fun testIsSubstituteWithActionAll() {
        assertTrue(mapper.isSubstituteWithActionAll(ACTION_ALL_SUBSTITUTE, setOf(ACTION_ALL)))
    }

    @Test
    fun testGetNamespaceFromRepositoryName() {
        val expectedNamespace = "company"
        val namespace = mapper.getNamespaceFromRepositoryName("$expectedNamespace/image")
        assertEquals(expectedNamespace, namespace)
    }

    @Test
    fun testGetNamespaceFromRepositoryNameWithoutNamespace() {
        val namespace = mapper.getNamespaceFromRepositoryName("image")
        assertNull(namespace)
    }

    @Test
    fun testGetNamespaceFromRepositoryNameWithNamespaceAndSegments() {
        val expectedNamespace = "company.com"
        val repositoryName = "$expectedNamespace/project1/teamA"
        val namespace = mapper.getNamespaceFromRepositoryName(repositoryName)
        assertEquals(expectedNamespace, namespace)
    }

    @Test
    fun testSubstituteRequestedActionsWithAll() {
        val requestedActions = listOf(ACTION_ALL)
        val expectedActions = setOf("pull", "push", "delete")
        val actions = mapper.substituteRequestedActions(requestedActions)
        assertEquals(expectedActions.sorted(), actions.sorted())
    }

    @Test
    fun testSubstituteRequestedActionsWithAllAndPush() {
        val requestedActions = listOf(ACTION_ALL, ACTION_PULL)
        val expectedActions = setOf("pull", "push", "delete")
        val actions = mapper.substituteRequestedActions(requestedActions)
        assertEquals(expectedActions.sorted(), actions.sorted())
    }

    @Test
    fun testAllowAll() {
        val user = Mockito.mock(UserModel::class.java)
        given(user.username).willReturn("Johnny")
        val expectedAccessItem = AbstractDockerScopeMapper.DockerScopeAccess("registry:catalog:*")
        val token = mapper.allowAll(DockerResponseToken(), expectedAccessItem, user, "Reason")
        assertEquals(1, token.accessItems.size)
        assertEquals(expectedAccessItem, token.accessItems.first())
    }

    @Test
    fun testAllowWithActions() {
        val user = Mockito.mock(UserModel::class.java)
        given(user.username).willReturn("Johnny")
        val expectedAccessItem = AbstractDockerScopeMapper.DockerScopeAccess("registry:catalog:*")
        val expectedActions = listOf(ACTION_DELETE)
        val token = mapper.allowWithActions(DockerResponseToken(), expectedAccessItem, expectedActions, user, "Reason")
        assertEquals(1, token.accessItems.size)
        assertEquals(expectedAccessItem, token.accessItems.first())
        assertEquals(expectedActions.sorted(), token.accessItems.first().actions.sorted())
    }

    @Test
    fun testDeny() {
        val user = Mockito.mock(UserModel::class.java)
        given(user.username).willReturn("Johnny")
        val expectedAccessItem = AbstractDockerScopeMapper.DockerScopeAccess("registry:catalog:*")
        val token = mapper.deny(DockerResponseToken(), expectedAccessItem, user, "Reason")
        assertEquals(0, token.accessItems.size)
    }
}