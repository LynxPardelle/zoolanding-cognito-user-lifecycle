from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"


class WorkflowContractTests(unittest.TestCase):
    def test_workflows_use_node24_native_actions_without_runtime_override(self):
        workflow_paths = sorted(WORKFLOW_DIR.glob("*.yml"))
        self.assertTrue(workflow_paths, "Expected GitHub workflow files")

        for workflow_path in workflow_paths:
            with self.subTest(workflow=workflow_path.name):
                workflow = workflow_path.read_text(encoding="utf-8")

                self.assertNotIn("FORCE_JAVASCRIPT_ACTIONS_TO_NODE24", workflow)
                self.assertNotIn("actions/setup-python@v5", workflow)
                self.assertNotIn("aws-actions/setup-sam@v2", workflow)

        combined_workflows = "\n".join(
            workflow_path.read_text(encoding="utf-8")
            for workflow_path in workflow_paths
        )
        self.assertIn("actions/setup-python@v6", combined_workflows)
        self.assertIn("aws-actions/setup-sam@v3", combined_workflows)


if __name__ == "__main__":
    unittest.main()
