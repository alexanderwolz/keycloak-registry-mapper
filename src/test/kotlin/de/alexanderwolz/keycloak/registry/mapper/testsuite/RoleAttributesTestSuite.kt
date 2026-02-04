package de.alexanderwolz.keycloak.registry.mapper.testsuite

import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_ALL
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_DELETE
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_PULL
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_PUSH
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.AUDIENCE_ADMIN
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.AUDIENCE_EDITOR
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.AUDIENCE_USER
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.NAMESPACE_SCOPE_GROUP
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ROLE_ATTRIBUTE_KEY_REGISTRY
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ROLE_ATTRIBUTE_PREFIX
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ROLE_ATTRIBUTE_VALUE_CATALOG
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ROLE_EDITOR
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/**
 * Tests for role attribute-based namespace permissions.
 *
 * Role attributes allow defining per-namespace permissions directly on roles.
 * Format: "registry:{namespace}" = "pull,push,delete" or "registry:{namespace}" = "*"
 *
 * Supported actions: pull, push, delete, * (expands to all actions)
 *
 * This test suite verifies:
 * - Role attributes grant access to namespaces (even without group membership)
 * - Role attributes define specific allowed actions for namespaces
 * - Role attributes combine with group-based access and global roles
 * - Multiple roles with different namespace permissions work correctly
 */
class RoleAttributesTestSuite : AbstractScopeMapperTestSuite() {

    companion object {
        private const val NAMESPACE_REPO1 = "repository-1"
        private const val NAMESPACE_REPO2 = "repository-2"
        private const val NAMESPACE_REPO3 = "repository-3"
        private const val IMAGE = "image"

        private const val GROUP_REPO1 = "registry-$NAMESPACE_REPO1"
        private const val GROUP_REPO2 = "registry-$NAMESPACE_REPO2"

        const val SCOPE_REPO1_ALL = "repository:$NAMESPACE_REPO1/$IMAGE:*"
        const val SCOPE_REPO1_PULL = "repository:$NAMESPACE_REPO1/$IMAGE:pull"
        const val SCOPE_REPO1_PUSH = "repository:$NAMESPACE_REPO1/$IMAGE:push"
        const val SCOPE_REPO1_DELETE = "repository:$NAMESPACE_REPO1/$IMAGE:delete"
        const val SCOPE_REPO1_PULL_PUSH = "repository:$NAMESPACE_REPO1/$IMAGE:pull,push"

        const val SCOPE_REPO2_ALL = "repository:$NAMESPACE_REPO2/$IMAGE:*"
        const val SCOPE_REPO2_PULL = "repository:$NAMESPACE_REPO2/$IMAGE:pull"
        const val SCOPE_REPO2_PUSH = "repository:$NAMESPACE_REPO2/$IMAGE:push"

        const val SCOPE_REPO3_ALL = "repository:$NAMESPACE_REPO3/$IMAGE:*"
        const val SCOPE_REPO3_PULL = "repository:$NAMESPACE_REPO3/$IMAGE:pull"
        const val SCOPE_REPO3_PUSH = "repository:$NAMESPACE_REPO3/$IMAGE:push"

        // Role attribute keys
        private const val ATTR_REPO1 = "${ROLE_ATTRIBUTE_PREFIX}$NAMESPACE_REPO1"
        private const val ATTR_REPO2 = "${ROLE_ATTRIBUTE_PREFIX}$NAMESPACE_REPO2"
        private const val ATTR_REPO3 = "${ROLE_ATTRIBUTE_PREFIX}$NAMESPACE_REPO3"

        // Catalog scope
        const val SCOPE_CATALOG = "registry:catalog:*"
    }

    @Nested
    inner class RoleAttributeGrantsAccessTests {
        @Test
        internal fun role_with_push_pull_attribute_grants_push_access_without_group() {
            // User has no groups but role with "registry:repository-1=pull,push"
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "repo1-role" to mapOf(ATTR_REPO1 to "pull,push")
            )
            setScope(SCOPE_REPO1_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun role_with_star_attribute_grants_all_actions_without_group() {
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "repo1-role" to mapOf(ATTR_REPO1 to "*")
            )
            setScope(SCOPE_REPO1_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun role_with_pull_only_attribute_grants_only_pull_access() {
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "repo2-role" to mapOf(ATTR_REPO2 to "pull")
            )
            setScope(SCOPE_REPO2_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun role_with_pull_only_attribute_denies_push() {
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "repo2-role" to mapOf(ATTR_REPO2 to "pull")
            )
            setScope(SCOPE_REPO2_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun role_with_push_delete_attribute_without_pull() {
            // Can have push,delete without pull
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "special-role" to mapOf(ATTR_REPO1 to "push,delete")
            )
            setScope(SCOPE_REPO1_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun role_with_push_delete_attribute_allows_push() {
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "special-role" to mapOf(ATTR_REPO1 to "push,delete")
            )
            setScope(SCOPE_REPO1_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun role_with_delete_only_attribute() {
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "delete-role" to mapOf(ATTR_REPO1 to "delete")
            )
            setScope(SCOPE_REPO1_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }
    }

    @Nested
    inner class MultipleNamespacePermissionsTests {
        @Test
        internal fun role_with_multiple_namespace_attributes() {
            // One role with "registry:repository-1=pull,push,delete" and "registry:repository-2=pull"
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "multi-namespace-role" to mapOf(
                    ATTR_REPO1 to "pull,push,delete",
                    ATTR_REPO2 to "pull"
                )
            )

            // Can push to repository-1
            setScope(SCOPE_REPO1_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun role_with_multiple_namespace_attributes_repo2_pull_only() {
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "multi-namespace-role" to mapOf(
                    ATTR_REPO1 to "pull,push,delete",
                    ATTR_REPO2 to "pull"
                )
            )

            // Can only pull from repository-2
            setScope(SCOPE_REPO2_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun role_with_multiple_namespace_attributes_repo2_can_pull() {
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "multi-namespace-role" to mapOf(
                    ATTR_REPO1 to "pull,push,delete",
                    ATTR_REPO2 to "pull"
                )
            )

            setScope(SCOPE_REPO2_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class CombineWithGroupsTests {
        @Test
        internal fun group_access_with_global_editor_role() {
            // User in group with global editor role (existing behavior)
            setGroups(GROUP_REPO1)
            setRoles(ROLE_EDITOR)
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setScope(SCOPE_REPO1_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun group_access_without_editor_role_only_pulls() {
            // User in group without editor role -> pull only
            setGroups(GROUP_REPO1)
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setScope(SCOPE_REPO1_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun group_access_with_role_attribute_adds_push() {
            // User in group without global editor, but has role attribute granting push
            setGroups(GROUP_REPO1)
            setRolesWithAttributes(
                "custom-role" to mapOf(ATTR_REPO1 to "push")
            )
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setScope(SCOPE_REPO1_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun group_access_combines_pull_from_group_and_push_from_attribute() {
            // User in group (gets pull) + role attribute (gets push)
            // Should get both pull and push
            setGroups(GROUP_REPO1)
            setRolesWithAttributes(
                "custom-role" to mapOf(ATTR_REPO1 to "push")
            )
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setScope(SCOPE_REPO1_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }

        @Test
        internal fun mixed_group_and_role_attribute_access() {
            // User in repository-1 group (pull only via group)
            // User has role with "registry:repository-3=pull,push" (push/pull to repo3 via attribute)
            setGroups(GROUP_REPO1)
            setRolesWithAttributes(
                "repo3-editor" to mapOf(ATTR_REPO3 to "pull,push")
            )
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)

            // Can only pull from repository-1 (group access, no push permission)
            setScope(SCOPE_REPO1_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun mixed_group_and_role_attribute_access_can_pull_from_group() {
            setGroups(GROUP_REPO1)
            setRolesWithAttributes(
                "repo3-editor" to mapOf(ATTR_REPO3 to "pull,push")
            )
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)

            // Can pull from repository-1
            setScope(SCOPE_REPO1_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun mixed_group_and_role_attribute_access_can_push_to_repo3() {
            setGroups(GROUP_REPO1)
            setRolesWithAttributes(
                "repo3-editor" to mapOf(ATTR_REPO3 to "pull,push")
            )
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)

            // Can push to repository-3 (role attribute access)
            setScope(SCOPE_REPO3_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }
    }

    @Nested
    inner class ComplexScenarioTests {
        @Test
        internal fun user_scenario_pull_from_groups_push_to_specific_via_attribute() {
            // Scenario: User in 2 groups with just pull, but has role attribute for push on one specific namespace
            // - User in registry-repository-1 and registry-repository-2 groups (pull only)
            // - User has role "special" with "registry:repository-3=pull,push"
            // Result: pull from repository-1/repository-2, push to repository-3

            setGroups(GROUP_REPO1, GROUP_REPO2)
            setRolesWithAttributes(
                "special" to mapOf(ATTR_REPO3 to "pull,push")
            )
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)

            // Can pull from repository-1 (group)
            setScope(SCOPE_REPO1_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_scenario_cannot_push_to_group_namespaces() {
            setGroups(GROUP_REPO1, GROUP_REPO2)
            setRolesWithAttributes(
                "special" to mapOf(ATTR_REPO3 to "pull,push")
            )
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)

            // Cannot push to repository-1 (no push permission)
            setScope(SCOPE_REPO1_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_scenario_can_push_to_attribute_namespace() {
            setGroups(GROUP_REPO1, GROUP_REPO2)
            setRolesWithAttributes(
                "special" to mapOf(ATTR_REPO3 to "pull,push")
            )
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)

            // Can push to repository-3 (role attribute)
            setScope(SCOPE_REPO3_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun global_editor_combined_with_attribute_pull_only() {
            // User has global editor role (push/delete for all group namespaces)
            // But for a specific namespace via attribute, only pull is allowed
            // Test that attribute restricts when accessing via attribute-only

            setRolesWithAttributes(
                ROLE_EDITOR to emptyMap(),
                "restricted" to mapOf(ATTR_REPO3 to "pull")
            )
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)

            // Accessing repository-3 namespace (no group) via attribute only
            // Should only get pull from attribute
            setScope(SCOPE_REPO3_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun global_editor_with_group_gets_full_access() {
            // User has global editor role + group membership
            setGroups(GROUP_REPO1)
            setRoles(ROLE_EDITOR)
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)

            setScope(SCOPE_REPO1_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }
    }

    @Nested
    inner class NoAccessTests {
        @Test
        internal fun no_group_no_attribute_denied() {
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            // No groups, no role attributes
            setScope(SCOPE_REPO3_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun wrong_namespace_attribute_denied() {
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "repo1-only" to mapOf(ATTR_REPO1 to "pull,push")
            )
            // Has repository-1 attribute but trying to access repository-3
            setScope(SCOPE_REPO3_PULL)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class ActionCombinationTests {
        @Test
        internal fun attribute_with_spaces_in_value() {
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "spaced-role" to mapOf(ATTR_REPO1 to "pull, push, delete")
            )
            setScope(SCOPE_REPO1_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun attribute_with_uppercase_actions() {
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "upper-role" to mapOf(ATTR_REPO1 to "PULL,PUSH")
            )
            setScope(SCOPE_REPO1_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }

        @Test
        internal fun multiple_roles_combine_actions() {
            // Two roles, each granting different actions
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "pull-role" to mapOf(ATTR_REPO1 to "pull"),
                "push-role" to mapOf(ATTR_REPO1 to "push")
            )
            setScope(SCOPE_REPO1_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    /**
     * Tests for catalog access via role attributes.
     *
     * The attribute key "registry" with value "catalog" grants catalog access
     * regardless of the global REGISTRY_CATALOG_AUDIENCE setting.
     */
    @Nested
    inner class CatalogAccessViaAttributeTests {

        @Test
        internal fun user_with_catalog_attribute_gets_catalog_access_when_audience_is_admin() {
            // User has no special role, but has catalog attribute
            // REGISTRY_CATALOG_AUDIENCE defaults to admin, so normally denied
            setAudience(AUDIENCE_ADMIN)
            setRolesWithAttributes(
                "catalog-role" to mapOf(ROLE_ATTRIBUTE_KEY_REGISTRY to ROLE_ATTRIBUTE_VALUE_CATALOG)
            )
            setScope(SCOPE_CATALOG)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun editor_with_catalog_attribute_gets_catalog_access_when_audience_is_admin() {
            // Editor would normally be denied when audience=admin
            setAudience(AUDIENCE_ADMIN)
            setRolesWithAttributes(
                ROLE_EDITOR to emptyMap(),
                "catalog-role" to mapOf(ROLE_ATTRIBUTE_KEY_REGISTRY to ROLE_ATTRIBUTE_VALUE_CATALOG)
            )
            setScope(SCOPE_CATALOG)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun user_without_catalog_attribute_denied_when_audience_is_admin() {
            // User has a role but no catalog attribute - should be denied
            setAudience(AUDIENCE_ADMIN)
            setRolesWithAttributes(
                "some-role" to mapOf(ATTR_REPO1 to "pull,push")
            )
            setScope(SCOPE_CATALOG)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_without_catalog_attribute_denied_when_audience_is_admin() {
            // Editor has no catalog attribute and audience=admin - should be denied
            setAudience(AUDIENCE_ADMIN)
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_CATALOG)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_without_catalog_attribute_allowed_when_audience_is_editor() {
            // Editor should be allowed via audience setting
            setAudience(AUDIENCE_EDITOR)
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_CATALOG)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun user_without_catalog_attribute_allowed_when_audience_is_user() {
            // Any user should be allowed when audience=user
            setAudience(AUDIENCE_USER)
            setRolesWithAttributes(
                "some-role" to emptyMap()
            )
            setScope(SCOPE_CATALOG)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun catalog_attribute_case_insensitive() {
            // Value check should be case-insensitive
            setAudience(AUDIENCE_ADMIN)
            setRolesWithAttributes(
                "catalog-role" to mapOf(ROLE_ATTRIBUTE_KEY_REGISTRY to "CATALOG")
            )
            setScope(SCOPE_CATALOG)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun wrong_attribute_value_denied() {
            // Key is "registry" but value is NOT "catalog" - should be denied
            setAudience(AUDIENCE_ADMIN)
            setRolesWithAttributes(
                "wrong-value-role" to mapOf(ROLE_ATTRIBUTE_KEY_REGISTRY to "something_else")
            )
            setScope(SCOPE_CATALOG)
            assertEmptyAccessItems()
        }

        @Test
        internal fun multiple_roles_one_with_catalog_attribute() {
            // User has multiple roles, only one grants catalog access
            setAudience(AUDIENCE_ADMIN)
            setRolesWithAttributes(
                "namespace-role" to mapOf(ATTR_REPO1 to "pull,push"),
                "catalog-role" to mapOf(ROLE_ATTRIBUTE_KEY_REGISTRY to ROLE_ATTRIBUTE_VALUE_CATALOG)
            )
            setScope(SCOPE_CATALOG)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun catalog_attribute_combined_with_namespace_attribute() {
            // User has both catalog access and namespace permissions via attributes
            setAudience(AUDIENCE_ADMIN)
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "multi-access-role" to mapOf(
                    ROLE_ATTRIBUTE_KEY_REGISTRY to ROLE_ATTRIBUTE_VALUE_CATALOG,
                    ATTR_REPO1 to "pull,push"
                )
            )
            // Can access catalog
            setScope(SCOPE_CATALOG)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun catalog_attribute_combined_with_namespace_attribute_can_push() {
            // Same user from above can also push to the namespace
            setAudience(AUDIENCE_ADMIN)
            setNamespaceScope(NAMESPACE_SCOPE_GROUP)
            setRolesWithAttributes(
                "multi-access-role" to mapOf(
                    ROLE_ATTRIBUTE_KEY_REGISTRY to ROLE_ATTRIBUTE_VALUE_CATALOG,
                    ATTR_REPO1 to "pull,push"
                )
            )
            // Can also push to repository-1
            setScope(SCOPE_REPO1_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }
    }
}
