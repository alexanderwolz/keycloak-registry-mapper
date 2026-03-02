package de.alexanderwolz.keycloak.registry.mapper.testsuite

import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_DELETE
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_PULL
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_PUSH
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.DEFAULT_REGISTRY_GROUP_PREFIX
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ROLE_EDITOR
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ROLE_USER
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class GroupOverrideTestSuite : AbstractScopeMapperTestSuite() {

    private val prefix = DEFAULT_REGISTRY_GROUP_PREFIX

    private val namespaceGroup = "$prefix$NAMESPACE"
    private val repoEditorGroup = "$prefix$NAMESPACE/$IMAGE/editor"
    private val repoUserGroup = "$prefix$NAMESPACE/$IMAGE/user"
    private val otherRepoEditorGroup = "$prefix$NAMESPACE/otherrepo/editor"
    private val deepRepoEditorGroup = "$prefix$NAMESPACE/team/$IMAGE/editor"
    private val deepRepoUserGroup = "$prefix$NAMESPACE/team/$IMAGE/user"

    // -------------------------------------------------------------------------
    // Repo-level editor override (client role: user) -> pull+push+delete
    // -------------------------------------------------------------------------

    @Nested
    inner class RepoEditorOverrideWithClientRoleUserTests {

        @Test
        internal fun repo_editor_override_client_user_on_scope_all() {
            setNestedGroups(repoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun repo_editor_override_client_user_on_scope_pull() {
            setNestedGroups(repoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun repo_editor_override_client_user_on_scope_push() {
            setNestedGroups(repoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun repo_editor_override_client_user_on_scope_delete() {
            setNestedGroups(repoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun repo_editor_override_client_user_on_scope_pull_push() {
            setNestedGroups(repoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    // -------------------------------------------------------------------------
    // Repo-level user override (client role: editor) -> pull only
    // -------------------------------------------------------------------------

    @Nested
    inner class RepoUserOverrideWithClientRoleEditorTests {

        @Test
        internal fun repo_user_override_client_editor_on_scope_all() {
            setNestedGroups(repoUserGroup)
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun repo_user_override_client_editor_on_scope_pull() {
            setNestedGroups(repoUserGroup)
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun repo_user_override_client_editor_on_scope_push() {
            setNestedGroups(repoUserGroup)
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun repo_user_override_client_editor_on_scope_delete() {
            setNestedGroups(repoUserGroup)
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun repo_user_override_client_editor_on_scope_pull_push() {
            setNestedGroups(repoUserGroup)
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceGroupPlusRepoOverrideTests {

        // namespace group (client role: user) + repo editor override
        // overridden repo: editor wins -> push allowed
        // other repos: client role user -> pull only

        @Test
        internal fun namespace_plus_repo_editor_override_on_overridden_repo_all() {
            setNestedGroups(namespaceGroup, repoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun namespace_plus_repo_editor_override_on_overridden_repo_push() {
            setNestedGroups(namespaceGroup, repoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun namespace_plus_repo_editor_override_on_other_repo_pull_allowed() {
            setNestedGroups(namespaceGroup, repoEditorGroup)
            setRoles(ROLE_USER)
            setScope("repository:$NAMESPACE/otherrepo:pull")
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun namespace_plus_repo_editor_override_on_other_repo_push_denied() {
            setNestedGroups(namespaceGroup, repoEditorGroup)
            setRoles(ROLE_USER)
            setScope("repository:$NAMESPACE/otherrepo:push")
            assertEmptyAccessItems()
        }

        // namespace group (client role: editor) + repo user override
        // overridden repo: user wins -> push denied
        // other repos: client role editor -> push allowed

        @Test
        internal fun namespace_plus_repo_user_override_on_overridden_repo_push_denied() {
            setNestedGroups(namespaceGroup, repoUserGroup)
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun namespace_plus_repo_user_override_on_other_repo_push_allowed() {
            setNestedGroups(namespaceGroup, repoUserGroup)
            setRoles(ROLE_EDITOR)
            setScope("repository:$NAMESPACE/otherrepo:push")
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }
    }

    // -------------------------------------------------------------------------
    // Repo override only (no namespace group)
    // Access granted only on specific repo, denied everywhere else
    // -------------------------------------------------------------------------

    @Nested
    inner class RepoOverrideOnlyWithoutNamespaceGroupTests {

        @Test
        internal fun repo_override_only_editor_on_overridden_repo_all() {
            setNestedGroups(repoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun repo_override_only_editor_on_overridden_repo_push() {
            setNestedGroups(repoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun repo_override_only_editor_on_other_repo_denied() {
            setNestedGroups(repoEditorGroup)
            setRoles(ROLE_USER)
            setScope("repository:$NAMESPACE/otherrepo:pull")
            assertEmptyAccessItems()
        }

        @Test
        internal fun repo_override_only_editor_on_other_namespace_denied() {
            setNestedGroups(repoEditorGroup)
            setRoles(ROLE_USER)
            setScope("repository:othernamespace/$NAMESPACE:pull")
            assertEmptyAccessItems()
        }

        @Test
        internal fun repo_override_only_user_on_overridden_repo_pull() {
            setNestedGroups(repoUserGroup)
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun repo_override_only_user_on_overridden_repo_push_denied() {
            setNestedGroups(repoUserGroup)
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun repo_override_only_user_on_other_repo_denied() {
            setNestedGroups(repoUserGroup)
            setRoles(ROLE_EDITOR)
            setScope("repository:$NAMESPACE/otherrepo:push")
            assertEmptyAccessItems()
        }
    }

    // -------------------------------------------------------------------------
    // Deep repo paths (namespace/team/image)
    // -------------------------------------------------------------------------

    @Nested
    inner class DeepRepoPathTests {

        @Test
        internal fun deep_repo_editor_override_on_scope_all() {
            setNestedGroups(deepRepoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_DEEP_REPO_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun deep_repo_editor_override_on_scope_push() {
            setNestedGroups(deepRepoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_DEEP_REPO_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun deep_repo_editor_override_on_scope_delete() {
            setNestedGroups(deepRepoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_DEEP_REPO_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun deep_repo_editor_override_on_scope_pull_push() {
            setNestedGroups(deepRepoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_DEEP_REPO_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }

        @Test
        internal fun deep_repo_editor_does_not_match_shallow_repo() {
            // group is for "johnny/team/image" but scope requests "johnny/image"
            setNestedGroups(deepRepoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun deep_repo_user_override_on_scope_pull() {
            setNestedGroups(deepRepoUserGroup)
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_DEEP_REPO_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun deep_repo_user_override_on_scope_push_denied() {
            setNestedGroups(deepRepoUserGroup)
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_DEEP_REPO_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun deep_repo_editor_with_namespace_group_on_deep_repo_push() {
            setNestedGroups(namespaceGroup, deepRepoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_DEEP_REPO_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun deep_repo_editor_with_namespace_group_shallow_repo_falls_back_to_client_role() {
            // deep override doesn't affect shallow repo -> client role user -> pull only
            setNestedGroups(namespaceGroup, deepRepoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }
    }

    // -------------------------------------------------------------------------
    // No matching group -> deny
    // -------------------------------------------------------------------------

    @Nested
    inner class NoMatchingGroupTests {

        @Test
        internal fun no_groups_denied() {
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun wrong_namespace_repo_override_denied() {
            setNestedGroups("${prefix}othernamespace/$IMAGE/editor")
            setRoles(ROLE_EDITOR)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun wrong_repo_override_denied() {
            setNestedGroups(otherRepoEditorGroup)
            setRoles(ROLE_USER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertEmptyAccessItems()
        }
    }
}
