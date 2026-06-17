from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TemplateContractTests(unittest.TestCase):
    def test_sam_template_has_no_public_api_events(self):
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")

        self.assertNotIn("AWS::Serverless::Api", template)
        self.assertNotIn("Type: Api", template)
        self.assertNotIn("Events:", template)

    def test_sam_template_grants_only_expected_cognito_mutations(self):
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")

        self.assertIn("RoleName:", template)
        self.assertIn("${AWS::StackName}-FunctionRole", template)
        self.assertIn("FunctionName:", template)
        self.assertIn("${AWS::StackName}-Function", template)
        self.assertIn("cognito-idp:AdminListGroupsForUser", template)
        self.assertIn("cognito-idp:AdminUpdateUserAttributes", template)
        self.assertIn("cognito-idp:AdminAddUserToGroup", template)
        self.assertNotIn("cognito-idp:AdminCreateUser", template)
        self.assertNotIn("cognito-idp:DeleteUserPool", template)
        self.assertNotIn("cognito-idp:CreateUserPool", template)

    def test_sam_template_uses_base64_profile_config_parameter(self):
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")

        self.assertIn("ProfileConfigJsonBase64:", template)
        self.assertIn("PROFILE_CONFIG_JSON_BASE64:", template)
        self.assertIn("Ref: ProfileConfigJsonBase64", template)
        self.assertNotIn("  ProfileConfigJson:\n", template)
        self.assertNotIn("PROFILE_CONFIG_JSON:\n", template)


if __name__ == "__main__":
    unittest.main()
