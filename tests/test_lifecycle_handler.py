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
    def __init__(self):
        self.calls = []

    def admin_update_user_attributes(self, **kwargs):
        self.calls.append(("admin_update_user_attributes", kwargs))
        return {}

    def admin_add_user_to_group(self, **kwargs):
        self.calls.append(("admin_add_user_to_group", kwargs))
        return {}


class LifecycleHandlerTests(unittest.TestCase):
    def run_handler(self, event, profile_config):
        fake = FakeCognitoClient()
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
