from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"


class WorkflowContractTests(unittest.TestCase):
    def test_workflows_force_github_actions_node24_runtime(self):
        workflow_paths = sorted(WORKFLOW_DIR.glob("*.yml"))
        self.assertTrue(workflow_paths, "Expected GitHub workflow files")

        for workflow_path in workflow_paths:
            with self.subTest(workflow=workflow_path.name):
                workflow = workflow_path.read_text(encoding="utf-8")
                before_jobs = workflow.split("\njobs:", maxsplit=1)[0]

                self.assertIn(
                    'env:\n  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"',
                    before_jobs,
                )


if __name__ == "__main__":
    unittest.main()
