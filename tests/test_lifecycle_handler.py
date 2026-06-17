import json
import os
import unittest
from unittest.mock import patch

import lambda_function as lifecycle


def base_event(trigger_source="PostConfirmation_ConfirmSignUp"):
    return {
        "version": "1",
        "region": "us-east-1",
        "userPoolId": "us-east-1_pool",
        "userName": "user@example.test",
        "triggerSource": trigger_source,
        "callerContext": {
            "awsSdkVersion": "aws-sdk-unknown-unknown",
            "clientId": "public-client-id",
        },
        "request": {
            "userAttributes": {
                "email": "user@example.test",
                "email_verified": "true",
            },
            "clientMetadata": {
                "tenantId": "evil-tenant",
                "groups": "Admins",
            },
        },
        "response": {},
    }


def config(**profile_overrides):
    profile = {
        "enabled": True,
        "environment": "test",
        "domain": "example.test",
        "authProfileId": "staff",
        "userPoolId": "us-east-1_pool",
        "clientIds": ["public-client-id"],
        "tenantId": "tenant-a",
        "tenantClaim": "custom:tenant_id",
        "allowedGroups": ["Editors", "Admins"],
        "defaultGroups": ["Editors"],
    }
    profile.update(profile_overrides)
    return json.dumps({"version": 1, "profiles": [profile]})


class FakeCognitoClient:
    def __init__(self, groups_by_username=None):
        self.calls = []
        self.groups_by_username = groups_by_username or {}

    def admin_update_user_attributes(self, **kwargs):
        self.calls.append(("admin_update_user_attributes", kwargs))
        return {}

    def admin_add_user_to_group(self, **kwargs):
        self.calls.append(("admin_add_user_to_group", kwargs))
        return {}

    def admin_list_groups_for_user(self, **kwargs):
        self.calls.append(("admin_list_groups_for_user", kwargs))
        groups = self.groups_by_username.get(kwargs["Username"], [])
        return {"Groups": [{"GroupName": group_name} for group_name in groups]}


class LifecycleHandlerTests(unittest.TestCase):
    def run_handler(self, event, profile_config, *, groups_by_username=None):
        fake = FakeCognitoClient(groups_by_username=groups_by_username)
        with patch.dict(os.environ, {
            "PROFILE_CONFIG_JSON": profile_config,
            "LOG_LEVEL": "ERROR",
        }, clear=True), patch.object(lifecycle, "_cognito_client", return_value=fake):
            result = lifecycle.lambda_handler(event, object())
        return result, fake

    def test_post_confirmation_assigns_tenant_and_default_groups_from_server_config(self):
        event = base_event()

        result, fake = self.run_handler(event, config())

        self.assertIs(result, event)
        self.assertEqual([call[0] for call in fake.calls], [
            "admin_update_user_attributes",
            "admin_add_user_to_group",
        ])
        self.assertEqual(fake.calls[0][1], {
            "UserPoolId": "us-east-1_pool",
            "Username": "user@example.test",
            "UserAttributes": [
                {"Name": "custom:tenant_id", "Value": "tenant-a"},
            ],
        })
        self.assertEqual(fake.calls[1][1], {
            "UserPoolId": "us-east-1_pool",
            "Username": "user@example.test",
            "GroupName": "Editors",
        })

    def test_profile_can_assign_generic_server_side_attributes(self):
        event = base_event()
        event["request"]["clientMetadata"] = {
            "attributes": {
                "custom:plan_id": "evil",
            },
        }

        result, fake = self.run_handler(event, config(
            attributes={
                "custom:tenant_id": "tenant-a",
                "custom:plan_id": "growth",
                "custom:dashboard_scope": "site-analytics",
            },
        ))

        self.assertIs(result, event)
        self.assertEqual(fake.calls[0][0], "admin_update_user_attributes")
        self.assertEqual(fake.calls[0][1]["UserAttributes"], [
            {"Name": "custom:tenant_id", "Value": "tenant-a"},
            {"Name": "custom:plan_id", "Value": "growth"},
            {"Name": "custom:dashboard_scope", "Value": "site-analytics"},
        ])
        self.assertNotIn("evil", json.dumps(fake.calls, sort_keys=True))

    def test_if_no_allowed_group_mode_preserves_existing_authorized_group(self):
        event = base_event("PostAuthentication_Authentication")

        result, fake = self.run_handler(
            event,
            config(repairOnPostAuthentication=True, groupAssignmentMode="ifNoAllowedGroup"),
            groups_by_username={"user@example.test": ["Admins"]},
        )

        self.assertIs(result, event)
        self.assertEqual([call[0] for call in fake.calls], [
            "admin_update_user_attributes",
            "admin_list_groups_for_user",
        ])

    def test_if_no_allowed_group_mode_adds_default_group_when_user_has_no_allowed_group(self):
        event = base_event("PostAuthentication_Authentication")

        _, fake = self.run_handler(
            event,
            config(repairOnPostAuthentication=True, groupAssignmentMode="ifNoAllowedGroup"),
            groups_by_username={"user@example.test": ["Unrelated"]},
        )

        self.assertEqual([call[0] for call in fake.calls], [
            "admin_update_user_attributes",
            "admin_list_groups_for_user",
            "admin_add_user_to_group",
        ])

    def test_client_metadata_cannot_select_tenant_or_groups(self):
        event = base_event()
        event["request"]["clientMetadata"] = {
            "domain": "example.test",
            "authProfileId": "staff",
            "tenantId": "evil",
            "groups": "Admins",
        }

        _, fake = self.run_handler(event, config(defaultGroups=["Editors"]))

        serialized_calls = json.dumps(fake.calls, sort_keys=True)
        self.assertNotIn("evil", serialized_calls)
        self.assertNotIn("Admins", serialized_calls)
        self.assertIn("tenant-a", serialized_calls)
        self.assertIn("Editors", serialized_calls)

    def test_default_groups_must_be_subset_of_allowed_groups(self):
        event = base_event()

        with self.assertRaises(lifecycle.AuthLifecycleConfigError):
            self.run_handler(event, config(defaultGroups=["Owners"]))

    def test_unmatched_pool_or_client_fails_closed(self):
        event = base_event()
        event["userPoolId"] = "us-east-1_other"

        with self.assertRaises(lifecycle.AuthLifecycleConfigError):
            self.run_handler(event, config())

    def test_multiple_matching_profiles_fail_closed(self):
        profile_config = json.loads(config())
        profile_config["profiles"].append(dict(profile_config["profiles"][0], domain="duplicate.test"))

        with self.assertRaises(lifecycle.AuthLifecycleConfigError):
            self.run_handler(base_event(), json.dumps(profile_config))

    def test_secret_like_profile_config_is_rejected(self):
        profile_config = json.loads(config())
        profile_config["profiles"][0]["clientSecret"] = "not-allowed"

        with self.assertRaises(lifecycle.AuthLifecycleConfigError):
            self.run_handler(base_event(), json.dumps(profile_config))

    def test_secret_like_generic_attribute_value_is_rejected(self):
        with self.assertRaises(lifecycle.AuthLifecycleConfigError):
            self.run_handler(base_event(), config(attributes={"custom:blocked_marker": "gho_short"}))

    def test_post_authentication_can_repair_existing_users_when_enabled(self):
        event = base_event("PostAuthentication_Authentication")
        event["request"]["userAttributes"].pop("custom:tenant_id", None)

        result, fake = self.run_handler(event, config(repairOnPostAuthentication=True))

        self.assertIs(result, event)
        self.assertEqual([call[0] for call in fake.calls], [
            "admin_update_user_attributes",
            "admin_add_user_to_group",
        ])

    def test_confirm_forgot_password_does_not_change_authorization_state(self):
        event = base_event("PostConfirmation_ConfirmForgotPassword")

        result, fake = self.run_handler(event, config())

        self.assertIs(result, event)
        self.assertEqual(fake.calls, [])


if __name__ == "__main__":
    unittest.main()
