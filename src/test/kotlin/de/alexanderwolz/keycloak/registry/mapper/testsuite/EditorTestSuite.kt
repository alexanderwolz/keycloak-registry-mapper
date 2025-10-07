package de.alexanderwolz.keycloak.registry.mapper.testsuite

import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_ALL
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_DELETE
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_PULL
import de.alexanderwolz.keycloak.registry.mapper.AbstractDockerScopeMapper.Companion.ACTION_PUSH
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.AUDIENCE_EDITOR
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.AUDIENCE_USER
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.NAMESPACE_SCOPE_DOMAIN
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.NAMESPACE_SCOPE_GROUP
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.NAMESPACE_SCOPE_SLD
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.NAMESPACE_SCOPE_USERNAME
import de.alexanderwolz.keycloak.registry.mapper.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ROLE_EDITOR
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class EditorTestSuite : AbstractScopeMapperTestSuite() {

    // Definition editor:  a person with role 'editor' but not 'admin'
    // Editors can pull, push and delete on repositories in their namespace

    override fun setRoles(vararg roleNames: String) {
        super.setRoles(ROLE_EDITOR, *roleNames)
    }

    @Test
    internal fun editor_no_groups_on_empty_scope() {
        assertEmptyAccessItems()
    }

    @Nested
    inner class RegistryTests {

        @Test
        internal fun editor_no_groups_on_registry_other_scope_all() {
            setScope(SCOPE_REGISTRY_OTHER_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_registry_other_scope_all() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_OTHER_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_namespace_groups_on_registry_other_scope_all() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_OTHER_ALL)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class RegistryCatalogTests {

        @Test
        internal fun editor_no_groups_on_registry_catalog_scope_all() {
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_registry_catalog_scope_all() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_namespace_groups_on_registry_catalog_scope_all() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class RegistryCatalogScopeForAudienceUserTests {

        @Test
        internal fun editor_no_groups_on_registry_catalog_scope_all_audience_user() {
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_USER)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun editor_other_groups_on_registry_catalog_scope_all_audience_user() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_USER)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun editor_namespace_groups_on_registry_catalog_scope_all_audience_user() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_USER)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }
    }

    @Nested
    inner class RegistryCatalogScopeForAudienceEditorTests {

        @Test
        internal fun editor_no_groups_on_registry_catalog_scope_all_audience_editor() {
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_EDITOR)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun editor_other_groups_on_registry_catalog_scope_all_audience_editor() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_EDITOR)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun editor_namespace_groups_on_registry_catalog_scope_all_audience_editor() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_EDITOR)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }
    }

    @Nested
    inner class DefaultRepositoryNoGroupsTests {

        @Test
        internal fun editor_no_groups_on_repository_scope_all_default() {
            setScope(SCOPE_REPO_DEFAULT_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_pull_default() {
            setScope(SCOPE_REPO_DEFAULT_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_push_default() {
            setScope(SCOPE_REPO_DEFAULT_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_delete_default() {
            setScope(SCOPE_REPO_DEFAULT_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_pull_push_default() {
            setScope(SCOPE_REPO_DEFAULT_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class DefaultRepositoryOtherGroupsTests {

        @Test
        internal fun editor_other_groups_on_repository_scope_all_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_pull_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_push_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_delete_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_pull_push_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class DefaultRepositoryNamespaceGroupsTests {

        @Test
        internal fun editor_namespace_groups_on_repository_scope_all_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_pull_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_push_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_delete_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_pull_push_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsTests {
        @Test
        internal fun editor_no_groups_on_repository_scope_all_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_pull_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_push_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_delete_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_pull_push_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsTests {
        @Test
        internal fun editor_other_groups_on_repository_scope_all_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_pull_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_push_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_delete_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_pull_push_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsTests {

        @Test
        internal fun editor_namespace_groups_on_repository_scope_all_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_pull_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_push_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_delete_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_pull_push_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsWithUsernameScopeTests {
        @Test
        internal fun editor_no_groups_on_repository_scope_all_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_pull_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_push_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_delete_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_pull_push_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsWithUsernameScopeTests {
        @Test
        internal fun editor_other_groups_on_repository_scope_all_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_pull_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_push_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_delete_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_pull_push_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsWithUsernameScopeTests {

        @Test
        internal fun editor_namespace_groups_on_repository_scope_all_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_pull_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_push_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_delete_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_pull_push_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsWithDomainScopeTests {
        @Test
        internal fun editor_no_groups_on_repository_scope_all_namespace_domain() {
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_pull_namespace_domain() {
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_push_namespace_domain() {
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_delete_namespace_domain() {
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_pull_push_namespace_domain() {
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsWithDomainScopeTests {
        @Test
        internal fun editor_other_groups_on_repository_scope_all_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_pull_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_delete_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_pull_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsWithDomainScopeTests {

        @Test
        internal fun editor_namespace_groups_on_repository_scope_all_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_pull_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_delete_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_pull_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsWithSldScopeTests {
        @Test
        internal fun editor_no_groups_on_repository_scope_all_namespace_sld() {
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_pull_namespace_sld() {
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_push_namespace_sld() {
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_delete_namespace_sld() {
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_pull_push_namespace_sld() {
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsWithSlDScopeTests {
        @Test
        internal fun editor_other_groups_on_repository_scope_all_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_pull_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_delete_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_pull_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsWithSldScopeTests {

        @Test
        internal fun editor_namespace_groups_on_repository_scope_all_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_pull_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_delete_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_pull_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsWithUsernameAndGroupScopeTests {
        @Test
        internal fun editor_no_groups_on_repository_scope_all_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_pull_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_push_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_delete_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_scope_pull_push_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH, ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsWithUsernameAndGroupScopeTests {
        @Test
        internal fun editor_other_groups_on_repository_scope_all_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_pull_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_push_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_delete_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_other_groups_on_repository_scope_pull_push_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsWithUsernameAndGroupScopeTests {

        @Test
        internal fun editor_namespace_groups_on_repository_scope_all_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_pull_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_push_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_delete_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_scope_pull_push_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }


    @Nested
    inner class DefaultRepositoryPluginNoGroupsTests {

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_all_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_pull_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_push_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_delete_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_pull_push_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class DefaultRepositoryPluginOtherGroupsTests {

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_all_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_pull_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_push_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_delete_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_pull_push_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class DefaultRepositoryPluginNamespaceGroupsTests {

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_all_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_pull_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_push_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_delete_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_DELETE)
            assertEmptyAccessItems()
        }


        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_pull_push_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsTests {

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_all_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_pull_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_push_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_delete_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_pull_push_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsTests {

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_all_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_pull_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_push_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_delete_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            assertEmptyAccessItems()
        }


        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_pull_push_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsTests {

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_all_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_pull_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_push_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_delete_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_pull_push_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsWithUsernameScopeTests {

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_all_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_pull_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_push_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_delete_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_pull_push_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsWithUsernameScopeTests {

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_all_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_pull_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_push_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_delete_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }


        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_pull_push_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsWithUsernameScopeTests {

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_all_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_pull_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_push_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_delete_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_pull_push_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsWithDomainScopeTests {

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_all_namespace_domain() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_pull_namespace_domain() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_push_namespace_domain() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_delete_namespace_domain() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_pull_push_namespace_domain() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsWithDomainScopeTests {

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_all_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_pull_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_delete_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }


        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_pull_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsWithDomainScopeTests {

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_all_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_pull_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_delete_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_pull_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsWithSldScopeTests {

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_all_namespace_sld() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_pull_namespace_sld() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_push_namespace_sld() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_delete_namespace_sld() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_pull_push_namespace_sld() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsWithSldScopeTests {

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_all_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_pull_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_delete_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }


        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_pull_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsWithSldScopeTests {

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_all_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_pull_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_delete_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_pull_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsWithUsernameAndGroupScopeTests {

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_all_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_pull_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_push_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_delete_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_no_groups_on_repository_plugin_scope_pull_push_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsWithUsernameAndGroupScopeTests {

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_all_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_pull_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_push_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_delete_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }


        @Test
        internal fun editor_other_groups_on_repository_plugin_scope_pull_push_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsWithUsernameAndGroupScopeTests {

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_all_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_pull_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_push_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_delete_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun editor_namespace_groups_on_repository_plugin_scope_pull_push_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

}