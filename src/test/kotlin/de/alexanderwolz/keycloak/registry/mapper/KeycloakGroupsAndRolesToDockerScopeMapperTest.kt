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
import java.util.stream.Stream
import kotlin.test.assertEquals

internal class KeycloakGroupsAndRolesToDockerScopeMapperTest {

    private val mapper = KeycloakGroupsAndRolesToDockerScopeMapper()

    @Test
    fun testGetUserNamespacesFromEmptyGroups() {
        val user = Mockito.mock(UserModel::class.java)
        given(user.groupsStream).willAnswer {
            Stream.empty<GroupModel>()
        }
        val actualGroupNames = mapper.getUserNamespacesFromGroups(user)
        assertEquals(0, actualGroupNames.size)
    }

    @Test
    fun testGetUserNamespacesFromGroupsAndSubgroups() {
        val user = Mockito.mock(UserModel::class.java)
        val groupWithPrefixSubgroup = "parentWithPrefixSubgroup"
        val groupNames = setOf("${mapper.groupPrefix}company", "otherGroup", groupWithPrefixSubgroup)
        val subgroupNames = setOf("${mapper.groupPrefix}subgroup", "otherSubgroup")
        given(user.groupsStream).willAnswer {
            groupNames.map { groupName ->
                Mockito.mock(GroupModel::class.java).also { parentGroup ->
                    given(parentGroup.name).willReturn(groupName)
                    if (groupName == groupWithPrefixSubgroup) {
                        given(parentGroup.subGroupsStream).willAnswer {
                            subgroupNames.map { subgroupName ->
                                Mockito.mock(GroupModel::class.java).also { childGroup ->
                                    given(childGroup.name).willReturn(subgroupName)
                                }
                            }.stream()
                        }
                    }
                }
            }.stream()
        }
        val expectedGroupNames = setOf("company", "subgroup")
        val actualGroupNames = mapper.getUserNamespacesFromGroups(user)
        assertEquals(expectedGroupNames.sorted(), actualGroupNames.sorted())
    }

    @Test
    fun testGetUserNamespacesFromSubgroupsOnly() {
        val user = Mockito.mock(UserModel::class.java)
        val groupWithPrefixSubgroup = "parentWithPrefixSubgroup"
        val groupNames = setOf("otherGroup1", "otherGroup2", groupWithPrefixSubgroup)
        val subgroupNames = setOf("${mapper.groupPrefix}subgroup1", "${mapper.groupPrefix}subgroup2", "otherSubgroup")
        given(user.groupsStream).willAnswer {
            groupNames.map { groupName ->
                Mockito.mock(GroupModel::class.java).also { parentGroup ->
                    given(parentGroup.name).willReturn(groupName)
                    if (groupName == groupWithPrefixSubgroup) {
                        given(parentGroup.subGroupsStream).willAnswer {
                            subgroupNames.map { subgroupName ->
                                Mockito.mock(GroupModel::class.java).also { childGroup ->
                                    given(childGroup.name).willReturn(subgroupName)
                                }
                            }.stream()
                        }
                    }
                }
            }.stream()
        }
        val expectedGroupNames = setOf("subgroup1", "subgroup2")
        val actualGroupNames = mapper.getUserNamespacesFromGroups(user)
        assertEquals(expectedGroupNames.sorted(), actualGroupNames.sorted())
    }

    @Test
    fun testGetUserNamespacesFromCustomGroupPrefix() {
        val customPrefix = "_MY-GROUP-PREFIX_".lowercase()
        mapper.groupPrefix = customPrefix
        assertEquals(mapper.groupPrefix, customPrefix)

        val user = Mockito.mock(UserModel::class.java)
        val groupNames = setOf("${customPrefix}company", "otherGroup")

        given(user.groupsStream).willAnswer {
            groupNames.map { groupName ->
                Mockito.mock(GroupModel::class.java).also { parentGroup ->
                    given(parentGroup.name).willReturn(groupName)
                }
            }.stream()
        }
        val expectedGroupNames = setOf("company")
        val actualGroupNames = mapper.getUserNamespacesFromGroups(user)
        assertEquals(expectedGroupNames.sorted(), actualGroupNames.sorted())
    }

    @Test
    fun testFilterAllowedActionsAllForUser() {
        val requestedActions = setOf(ACTION_ALL)
        val clientRoleNames = emptySet<String>()
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPullForUser() {
        val requestedActions = setOf(ACTION_PULL)
        val clientRoleNames = emptySet<String>()
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPushForUser() {
        val requestedActions = setOf(ACTION_PUSH)
        val clientRoleNames = emptySet<String>()
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = emptySet<String>()
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsDeleteForUser() {
        val requestedActions = setOf(ACTION_DELETE)
        val clientRoleNames = emptySet<String>()
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = emptySet<String>()
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPullPushForUser() {
        val requestedActions = setOf(ACTION_PULL, ACTION_PUSH)
        val clientRoleNames = emptySet<String>()
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPullPushDeleteForUser() {
        val requestedActions = setOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        val clientRoleNames = emptySet<String>()
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsAllForEditor() {
        val requestedActions = setOf(ACTION_ALL)
        val clientRoleNames = setOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_ALL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPullForEditor() {
        val requestedActions = setOf(ACTION_PULL)
        val clientRoleNames = setOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPushForEditor() {
        val requestedActions = setOf(ACTION_PUSH)
        val clientRoleNames = setOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PUSH)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsDeleteForEditor() {
        val requestedActions = setOf(ACTION_DELETE)
        val clientRoleNames = setOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_DELETE)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPullPushForEditor() {
        val requestedActions = setOf(ACTION_PULL, ACTION_PUSH)
        val clientRoleNames = setOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL, ACTION_PUSH)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPullPushDeleteForEditor() {
        val requestedActions = setOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        val clientRoleNames = setOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

}