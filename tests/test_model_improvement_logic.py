import unittest

from analysis_schema import triage_state, triage_state_two_model_fused
from build_dataset import _label_quality_flags, _normalize_benign_subtype
from fusion import build_uncertainty_gate, ensemble_score_logit, final_triage
from utils.graph_attr_profile import apply_graph_attr_profile
import torch


class GovernanceLogicTests(unittest.TestCase):
    def test_novirus_controls_default_to_ambiguous_subtype(self):
        self.assertEqual(
            _normalize_benign_subtype("", 0, folder_name="Cerber-NoVirus"),
            "ambiguous_novirus_control",
        )

    def test_admin_tooling_maps_to_hard_benign(self):
        self.assertEqual(
            _normalize_benign_subtype("", 0, folder_name="Defender-Admin-Tool"),
            "hard_benign_admin_tooling",
        )

    def test_label_quality_flags_mark_ambiguous_novirus_controls(self):
        flagged, reasons = _label_quality_flags(
            {
                "name": "Cerber-NoVirus",
                "family": "cerber",
                "label": 0,
                "label_source": "name_inference",
                "benign_subtype": "",
            }
        )
        self.assertTrue(flagged)
        self.assertIn("ambiguous_novirus_control", reasons)


class TriageLogicTests(unittest.TestCase):
    def test_triage_state_uses_custom_thresholds(self):
        state = triage_state(
            0.76,
            0.31,
            malware_low=0.35,
            malware_high=0.70,
            benign_low=0.40,
            benign_high=0.75,
        )
        self.assertEqual(state, "likely_malicious")

    def test_uncertainty_gate_forces_review(self):
        gate = build_uncertainty_gate(
            mc_mal_variance=0.001,
            mc_ben_variance=0.05,
            binary_dual_gap=0.1,
            dual_score_margin=0.25,
            mc_variance_threshold=0.03,
        )
        self.assertTrue(gate.triggered)
        self.assertIn("high_mc_dropout_variance", gate.reason)
        self.assertEqual(
            final_triage(0.9, low=0.4, high=0.65, uncertainty_gate=gate),
            "needs_analyst_review",
        )
        self.assertEqual(
            triage_state_two_model_fused(
                "likely_benign",
                "needs_analyst_review",
                False,
                uncertainty_gate_triggered=True,
            ),
            "needs_analyst_review",
        )

    def test_calibrated_mode_skips_disagreement_when_binary_saturated(self):
        gate = build_uncertainty_gate(
            binary_dual_gap=0.9,
            dual_score_margin=0.2,
            binary_probability=0.99,
            disagreement_threshold=0.35,
            abstention_mode="calibrated",
        )
        self.assertNotIn("binary_dual_disagreement", (gate.reason or ""))

    def test_no_manifest_leakage_zeros_manifest_indices(self):
        ga = torch.ones(1, 61)
        masked = apply_graph_attr_profile(ga, "no_manifest_leakage")
        self.assertEqual(float(masked[0, 0]), 0.0)
        self.assertEqual(float(masked[0, 4]), 1.0)

    def test_ensemble_score_logit_in_unit_interval(self):
        s = ensemble_score_logit(0.9, 0.1, 0.5)
        self.assertGreaterEqual(s, 0.0)
        self.assertLessEqual(s, 1.0)


if __name__ == "__main__":
    unittest.main()
