package de.alexanderwolz.keycloak.docker.mapping.testsuite

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
import de.alexanderwolz.keycloak.registry.mapper.testsuite.AbstractScopeMapperTestSuite
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class UserTestSuite : AbstractScopeMapperTestSuite() {

    // Definition user:  a person without 'editor' or 'admin' role
    // Users are only allowed to access read-only (pull) on their namespace
    // except: audience is set to user for registry:catalog:*
    // namespace can be configured to either be 'username' and/or 'group'

    // we test users (clients without roles) with:
    // 1. no groups at all
    // 2. other groups than the scope
    // 3. namespace group matching the scope
    // 4. special case: Audience set to 'editor' or 'user'

    // pull push delete *

    @Test
    internal fun user_no_groups_on_empty_scope() {
        assertEmptyAccessItems()
    }

    @Nested
    inner class RegistryTests {

        @Test
        internal fun user_no_groups_on_registry_other_scope_all() {
            setScope(SCOPE_REGISTRY_OTHER_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_registry_other_scope_all() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_OTHER_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_registry_other_scope_all() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_OTHER_ALL)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class RegistryCatalogTests {

        @Test
        internal fun user_no_groups_on_registry_catalog_scope_all() {
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_registry_catalog_scope_all() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_registry_catalog_scope_all() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class RegistryCatalogScopeForAudienceUserTests {

        @Test
        internal fun user_no_groups_on_registry_catalog_scope_all_audience_user() {
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_USER)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun user_other_groups_on_registry_catalog_scope_all_audience_user() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_USER)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun user_namespace_groups_on_registry_catalog_scope_all_audience_user() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_USER)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }
    }

    @Nested
    inner class RegistryCatalogScopeForAudienceEditorTests {

        @Test
        internal fun user_no_groups_on_registry_catalog_scope_all_audience_editor() {
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_EDITOR)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_registry_catalog_scope_all_audience_editor() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_EDITOR)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_registry_catalog_scope_all_audience_editor() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_EDITOR)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class DefaultRepositoryNoGroupsTests {

        @Test
        internal fun user_no_groups_on_repository_scope_all_default() {
            setScope(SCOPE_REPO_DEFAULT_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_scope_pull_default() {
            setScope(SCOPE_REPO_DEFAULT_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_scope_push_default() {
            setScope(SCOPE_REPO_DEFAULT_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_scope_delete_default() {
            setScope(SCOPE_REPO_DEFAULT_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_scope_pull_push_default() {
            setScope(SCOPE_REPO_DEFAULT_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class DefaultRepositoryOtherGroupsTests {

        @Test
        internal fun user_other_groups_on_repository_scope_all_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_scope_pull_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_scope_push_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_scope_delete_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_scope_pull_push_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class DefaultRepositoryNamespaceGroupsTests {

        @Test
        internal fun user_namespace_groups_on_repository_scope_all_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_pull_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_push_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_delete_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_pull_push_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsTests {
        @Test
        internal fun user_no_groups_on_repository_scope_all_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_scope_pull_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_scope_push_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_scope_delete_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_scope_pull_push_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsTests {
        @Test
        internal fun user_other_groups_on_repository_scope_all_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_scope_pull_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_scope_push_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_scope_delete_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_scope_pull_push_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsTests {

        @Test
        internal fun user_namespace_groups_on_repository_scope_all_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_pull_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_push_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_delete_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_pull_push_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsWithUsernameScopeTests {
        @Test
        internal fun user_no_groups_on_repository_scope_all_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun user_no_groups_on_repository_scope_pull_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_no_groups_on_repository_scope_push_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun user_no_groups_on_repository_scope_delete_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun user_no_groups_on_repository_scope_pull_push_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsWithUsernameScopeTests {
        @Test
        internal fun user_other_groups_on_repository_scope_all_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun user_other_groups_on_repository_scope_pull_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_other_groups_on_repository_scope_push_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun user_other_groups_on_repository_scope_delete_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun user_other_groups_on_repository_scope_pull_push_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsWithUsernameScopeTests {

        @Test
        internal fun user_namespace_groups_on_repository_scope_all_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_pull_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_push_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_delete_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_pull_push_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsWithDomainScopeTests {
        @Test
        internal fun user_no_groups_on_repository_scope_all_namespace_domain() {
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_no_groups_on_repository_scope_pull_namespace_domain() {
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_no_groups_on_repository_scope_push_namespace_domain() {
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_scope_delete_namespace_domain() {
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_scope_pull_push_namespace_domain() {
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsWithDomainScopeTests {
        @Test
        internal fun user_other_groups_on_repository_scope_all_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_other_groups_on_repository_scope_pull_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_other_groups_on_repository_scope_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_scope_delete_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_scope_pull_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsWithDomainScopeTests {

        @Test
        internal fun user_namespace_groups_on_repository_scope_all_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_pull_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_delete_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_pull_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DOMAIN_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsWithSLDScopeTests {
        @Test
        internal fun user_no_groups_on_repository_scope_all_namespace_sld() {
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_no_groups_on_repository_scope_pull_namespace_sld() {
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_no_groups_on_repository_scope_push_namespace_sld() {
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_scope_delete_namespace_sld() {
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_scope_pull_push_namespace_sld() {
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsWithSldScopeTests {
        @Test
        internal fun user_other_groups_on_repository_scope_all_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_other_groups_on_repository_scope_pull_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_other_groups_on_repository_scope_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_scope_delete_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_scope_pull_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsWithSldScopeTests {

        @Test
        internal fun user_namespace_groups_on_repository_scope_all_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_pull_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_delete_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_pull_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsWithUsernameAndGroupScopeTests {
        @Test
        internal fun user_no_groups_on_repository_scope_all_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun user_no_groups_on_repository_scope_pull_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_no_groups_on_repository_scope_push_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun user_no_groups_on_repository_scope_delete_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun user_no_groups_on_repository_scope_pull_push_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsWithUsernameAndGroupScopeTests {
        @Test
        internal fun user_other_groups_on_repository_scope_all_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun user_other_groups_on_repository_scope_pull_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_other_groups_on_repository_scope_push_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun user_other_groups_on_repository_scope_delete_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun user_other_groups_on_repository_scope_pull_push_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsWithUsernameAndGroupScopeTests {

        @Test
        internal fun user_namespace_groups_on_repository_scope_all_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_pull_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_push_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_delete_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun user_namespace_groups_on_repository_scope_pull_push_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }


    @Nested
    inner class DefaultRepositoryPluginNoGroupsTests {

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_all_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_pull_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_push_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_delete_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_pull_push_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class DefaultRepositoryPluginOtherGroupsTests {

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_all_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_pull_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_push_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_delete_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_pull_push_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class DefaultRepositoryPluginNamespaceGroupsTests {

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_all_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_pull_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_push_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_delete_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_DELETE)
            assertEmptyAccessItems()
        }


        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_pull_push_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsTests {

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_all_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_pull_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_push_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_delete_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_pull_push_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsTests {

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_all_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_pull_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_push_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_delete_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            assertEmptyAccessItems()
        }


        @Test
        internal fun user_other_groups_on_repository_plugin_scope_pull_push_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            assertEmptyAccessItems()
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsTests {

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_all_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_pull_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_push_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_delete_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_pull_push_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsWithUsernameScopeTests {

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_all_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_pull_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_push_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_delete_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_pull_push_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsWithUsernameScopeTests {

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_all_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_pull_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_push_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_delete_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }


        @Test
        internal fun user_other_groups_on_repository_plugin_scope_pull_push_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsWithUsernameScopeTests {

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_all_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_pull_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_push_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_delete_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_pull_push_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsWithDomainScopeTests {

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_all_namespace_domain() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_pull_namespace_domain() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_push_namespace_domain() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_delete_namespace_domain() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_pull_push_namespace_domain() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsWithDomainScopeTests {

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_all_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_pull_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_delete_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertEmptyAccessItems()
        }


        @Test
        internal fun user_other_groups_on_repository_plugin_scope_pull_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsWithDomainScopeTests {

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_all_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_pull_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_delete_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_pull_push_namespace_domain() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DOMAIN_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_DOMAIN)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsWithSldScopeTests {

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_all_namespace_sld() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_pull_namespace_sld() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_push_namespace_sld() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_delete_namespace_sld() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_pull_push_namespace_sld() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsWithSldScopeTests {

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_all_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_pull_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_delete_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertEmptyAccessItems()
        }


        @Test
        internal fun user_other_groups_on_repository_plugin_scope_pull_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsWithSldScopeTests {

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_all_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_pull_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_delete_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertEmptyAccessItems()
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_pull_push_namespace_sld() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_SLD)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsWithUsernameAndGroupScopeTests {

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_all_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_pull_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_push_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_delete_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun user_no_groups_on_repository_plugin_scope_pull_push_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsWithUsernameAndGroupScopeTests {

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_all_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_pull_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_push_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun user_other_groups_on_repository_plugin_scope_delete_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }


        @Test
        internal fun user_other_groups_on_repository_plugin_scope_pull_push_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsWithUsernameAndGroupScopeTests {

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_all_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_pull_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_push_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_delete_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun user_namespace_groups_on_repository_plugin_scope_pull_push_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }
}