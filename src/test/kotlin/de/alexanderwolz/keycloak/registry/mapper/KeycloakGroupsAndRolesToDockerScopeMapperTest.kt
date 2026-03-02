package de.alexanderwolz.keycloak.registry.mapper

import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_ALL
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_DELETE
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_PULL
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_PUSH
import org.junit.jupiter.api.Test
import org.keycloak.models.GroupModel
import org.keycloak.models.UserModel
import org.mockito.Mockito
import org.mockito.kotlin.given
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

internal class KeycloakGroupsAndRolesToDockerScopeMapperTest {

    private val mapper = KeycloakGroupsAndRolesToDockerScopeMapper()

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private fun mockGroup(name: String, parent: GroupModel? = null): GroupModel {
        return Mockito.mock(GroupModel::class.java).also { group ->
            given(group.name).willReturn(name)
            given(group.parent).willReturn(parent)
        }
    }

    private fun mockUser(vararg groups: GroupModel): UserModel {
        return Mockito.mock(UserModel::class.java).also { user ->
            given(user.groupsStream).willAnswer { groups.toList().stream() }
        }
    }

    // -------------------------------------------------------------------------
    // buildGroupPath
    // -------------------------------------------------------------------------

    @Test
    fun testBuildGroupPathTopLevel() {
        val group = mockGroup("registry-company1")
        assertEquals("registry-company1", mapper.buildGroupPath(group))
    }

    @Test
    fun testBuildGroupPathWithParent() {
        val parent = mockGroup("registry-company1")
        val child = mockGroup("editor", parent)
        assertEquals("registry-company1/editor", mapper.buildGroupPath(child))
    }

    @Test
    fun testBuildGroupPathWithGrandParent() {
        val grandParent = mockGroup("registry-company1")
        val parent = mockGroup("myrepo", grandParent)
        val child = mockGroup("editor", parent)
        assertEquals("registry-company1/myrepo/editor", mapper.buildGroupPath(child))
    }

    @Test
    fun testBuildGroupPathDeepNesting() {
        val level1 = mockGroup("registry-company1")
        val level2 = mockGroup("team", level1)
        val level3 = mockGroup("myrepo", level2)
        val level4 = mockGroup("user", level3)
        assertEquals("registry-company1/team/myrepo/user", mapper.buildGroupPath(level4))
    }

    // -------------------------------------------------------------------------
    // parseGroupPath
    // -------------------------------------------------------------------------

    @Test
    fun testParseGroupPathPlainNamespace() {
        val result = mapper.parseGroupPath("registry-company1")
        assertNotNull(result)
        assertEquals("company1", result.namespace)
        assertNull(result.repoPath)
        assertEquals(false, result.isEditor)
        assertEquals(false, result.hasExplicitRole)
    }

    @Test
    fun testParseGroupPathNamespaceUserLeaf() {
        val result = mapper.parseGroupPath("registry-company1/user")
        assertNotNull(result)
        assertEquals("company1", result.namespace)
        assertNull(result.repoPath)
        assertEquals(false, result.isEditor)
        assertEquals(true, result.hasExplicitRole)
    }

    @Test
    fun testParseGroupPathNamespaceEditorLeaf() {
        val result = mapper.parseGroupPath("registry-company1/editor")
        assertNotNull(result)
        assertEquals("company1", result.namespace)
        assertNull(result.repoPath)
        assertEquals(true, result.isEditor)
        assertEquals(true, result.hasExplicitRole)
    }

    @Test
    fun testParseGroupPathRepoLevelUser() {
        val result = mapper.parseGroupPath("registry-company1/myrepo/user")
        assertNotNull(result)
        assertEquals("company1", result.namespace)
        assertEquals("myrepo", result.repoPath)
        assertEquals(false, result.isEditor)
        assertEquals(true, result.hasExplicitRole)
    }

    @Test
    fun testParseGroupPathRepoLevelEditor() {
        val result = mapper.parseGroupPath("registry-company1/myrepo/editor")
        assertNotNull(result)
        assertEquals("company1", result.namespace)
        assertEquals("myrepo", result.repoPath)
        assertEquals(true, result.isEditor)
        assertEquals(true, result.hasExplicitRole)
    }

    @Test
    fun testParseGroupPathDeepRepoPath() {
        val result = mapper.parseGroupPath("registry-company1/team/myrepo/editor")
        assertNotNull(result)
        assertEquals("company1", result.namespace)
        assertEquals("team/myrepo", result.repoPath)
        assertEquals(true, result.isEditor)
        assertEquals(true, result.hasExplicitRole)
    }

    @Test
    fun testParseGroupPathWithLeadingSlash() {
        val result = mapper.parseGroupPath("/registry-company1/myrepo/editor")
        assertNotNull(result)
        assertEquals("company1", result.namespace)
        assertEquals("myrepo", result.repoPath)
        assertEquals(true, result.isEditor)
    }

    @Test
    fun testParseGroupPathIgnoresNonPrefixedGroup() {
        assertNull(mapper.parseGroupPath("othergroup/editor"))
    }

    @Test
    fun testParseGroupPathIgnoresInvalidRoleLeaf() {
        assertNull(mapper.parseGroupPath("registry-company1/admin"))
    }

    @Test
    fun testParseGroupPathIgnoresEmptyNamespace() {
        assertNull(mapper.parseGroupPath("registry-"))
    }

    @Test
    fun testParseGroupPathCustomPrefix() {
        mapper.groupPrefix = "myprefix-"
        val result = mapper.parseGroupPath("myprefix-company1/editor")
        assertNotNull(result)
        assertEquals("company1", result.namespace)
        mapper.groupPrefix = KeycloakGroupsAndRolesToDockerScopeMapper.DEFAULT_REGISTRY_GROUP_PREFIX
    }

    // -------------------------------------------------------------------------
    // getUserGroupAccesses
    // -------------------------------------------------------------------------

    @Test
    fun testGetUserGroupAccessesEmpty() {
        val user = mockUser()
        assertEquals(0, mapper.getUserGroupAccesses(user).size)
    }

    @Test
    fun testGetUserGroupAccessesPlainNamespaceGroup() {
        val group = mockGroup("registry-company1")
        val user = mockUser(group)
        val accesses = mapper.getUserGroupAccesses(user)
        assertEquals(1, accesses.size)
        assertEquals("company1", accesses.first().namespace)
        assertNull(accesses.first().repoPath)
        assertEquals(false, accesses.first().hasExplicitRole)
    }

    @Test
    fun testGetUserGroupAccessesWithRoleLeaf() {
        val parent = mockGroup("registry-company1")
        val child = mockGroup("editor", parent)
        val user = mockUser(parent, child)
        val accesses = mapper.getUserGroupAccesses(user)
        assertEquals(2, accesses.size)
        val namespaceAccess = accesses.find { !it.hasExplicitRole }
        assertNotNull(namespaceAccess)
        assertEquals("company1", namespaceAccess.namespace)
        val roleAccess = accesses.find { it.hasExplicitRole && it.repoPath == null }
        assertNotNull(roleAccess)
        assertEquals(true, roleAccess.isEditor)
    }

    @Test
    fun testGetUserGroupAccessesWithRepoOverride() {
        val parent = mockGroup("registry-company1")
        val repoGroup = mockGroup("myrepo", parent)
        val roleGroup = mockGroup("editor", repoGroup)
        val user = mockUser(parent, roleGroup)
        val accesses = mapper.getUserGroupAccesses(user)
        assertEquals(2, accesses.size)
        val repoAccess = accesses.find { it.repoPath == "myrepo" }
        assertNotNull(repoAccess)
        assertEquals("company1", repoAccess.namespace)
        assertEquals(true, repoAccess.isEditor)
        assertEquals(true, repoAccess.hasExplicitRole)
    }

    @Test
    fun testGetUserGroupAccessesIgnoresNonPrefixedGroups() {
        val otherGroup = mockGroup("someothergroup")
        val user = mockUser(otherGroup)
        assertEquals(0, mapper.getUserGroupAccesses(user).size)
    }

    @Test
    fun testGetUserGroupAccessesWithCustomPrefix() {
        val customPrefix = "_my-group-prefix_"
        mapper.groupPrefix = customPrefix
        val group = mockGroup("${customPrefix}company")
        val user = mockUser(group)
        val accesses = mapper.getUserGroupAccesses(user)
        assertEquals(1, accesses.size)
        assertEquals("company", accesses.first().namespace)
        mapper.groupPrefix = KeycloakGroupsAndRolesToDockerScopeMapper.DEFAULT_REGISTRY_GROUP_PREFIX
    }

    @Test
    fun testGetUserGroupAccessesNamespaceOnlyReturnsNoRepoPath() {
        val group = mockGroup("${mapper.groupPrefix}company")
        val user = mockUser(group)
        val accesses = mapper.getUserGroupAccesses(user)
        assertEquals(1, accesses.size)
        assertNull(accesses.first().repoPath)
    }

    @Test
    fun testGetUserGroupAccessesRepoGroupDoesNotContributeNamespace() {
        // user is only member of the leaf role group, not of the namespace group itself
        val namespaceGroup = mockGroup("${mapper.groupPrefix}company")
        val repoGroup = mockGroup("myrepo", namespaceGroup)
        val roleGroup = mockGroup("editor", repoGroup)
        val user = mockUser(roleGroup)
        val accesses = mapper.getUserGroupAccesses(user)
        assertEquals(1, accesses.size)
        assertEquals("myrepo", accesses.first().repoPath)
        assertNull(accesses.find { it.repoPath == null })
    }

    // -------------------------------------------------------------------------
    // getRepoPathFromRepositoryName
    // -------------------------------------------------------------------------

    @Test
    fun testGetRepoPathSimple() {
        assertEquals("myrepo", mapper.getRepoPathFromRepositoryName("namespace/myrepo"))
    }

    @Test
    fun testGetRepoPathNested() {
        assertEquals("team/myrepo", mapper.getRepoPathFromRepositoryName("namespace/team/myrepo"))
    }

    @Test
    fun testGetRepoPathNoNamespace() {
        assertNull(mapper.getRepoPathFromRepositoryName("image"))
    }

    // -------------------------------------------------------------------------
    // filterAllowedActions
    // -------------------------------------------------------------------------

    @Test
    fun testFilterAllowedActionsAllForUser() {
        assertEquals(listOf(ACTION_PULL), mapper.filterAllowedActions(setOf(ACTION_ALL), isEditor = false).sorted())
    }

    @Test
    fun testFilterAllowedActionsPullForUser() {
        assertEquals(listOf(ACTION_PULL), mapper.filterAllowedActions(setOf(ACTION_PULL), isEditor = false).sorted())
    }

    @Test
    fun testFilterAllowedActionsPushForUser() {
        assertEquals(emptyList<String>(), mapper.filterAllowedActions(setOf(ACTION_PUSH), isEditor = false).sorted())
    }

    @Test
    fun testFilterAllowedActionsDeleteForUser() {
        assertEquals(emptyList<String>(), mapper.filterAllowedActions(setOf(ACTION_DELETE), isEditor = false).sorted())
    }

    @Test
    fun testFilterAllowedActionsPullPushForUser() {
        assertEquals(listOf(ACTION_PULL), mapper.filterAllowedActions(setOf(ACTION_PULL, ACTION_PUSH), isEditor = false).sorted())
    }

    @Test
    fun testFilterAllowedActionsPullPushDeleteForUser() {
        assertEquals(listOf(ACTION_PULL), mapper.filterAllowedActions(setOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE), isEditor = false).sorted())
    }

    @Test
    fun testFilterAllowedActionsAllForEditor() {
        assertEquals(listOf(ACTION_ALL), mapper.filterAllowedActions(setOf(ACTION_ALL), isEditor = true).sorted())
    }

    @Test
    fun testFilterAllowedActionsPullForEditor() {
        assertEquals(listOf(ACTION_PULL), mapper.filterAllowedActions(setOf(ACTION_PULL), isEditor = true).sorted())
    }

    @Test
    fun testFilterAllowedActionsPushForEditor() {
        assertEquals(listOf(ACTION_PUSH), mapper.filterAllowedActions(setOf(ACTION_PUSH), isEditor = true).sorted())
    }

    @Test
    fun testFilterAllowedActionsDeleteForEditor() {
        assertEquals(listOf(ACTION_DELETE), mapper.filterAllowedActions(setOf(ACTION_DELETE), isEditor = true).sorted())
    }

    @Test
    fun testFilterAllowedActionsPullPushForEditor() {
        assertEquals(listOf(ACTION_PULL, ACTION_PUSH).sorted(), mapper.filterAllowedActions(setOf(ACTION_PULL, ACTION_PUSH), isEditor = true).sorted())
    }

    @Test
    fun testFilterAllowedActionsPullPushDeleteForEditor() {
        assertEquals(listOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE).sorted(), mapper.filterAllowedActions(setOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE), isEditor = true).sorted())
    }
}
