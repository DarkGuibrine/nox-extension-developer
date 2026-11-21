from contextlib import redirect_stdout
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import nox
import nox_matrix


class CliAndMatrixTests(unittest.TestCase):
    def test_matrix_0001_to_1200_completeness_semantic_bindings_and_three_counters(self):
        summary = nox_matrix.validate_matrix()
        self.assertEqual(summary['status'], 'PASS')
        self.assertEqual(summary['missing_0001_1000'], [])
        self.assertEqual(summary['duplicates'], 0)
        self.assertEqual(summary['inconsistent_items'], [])
        self.assertEqual(summary['ORIGINAL_IMPLEMENTADO'], 1000)
        self.assertEqual(summary['NOVO_IMPLEMENTADO'], 200)
        self.assertEqual(summary['TOTAL_VALIDO'], 1200)
        self.assertEqual(summary['autonomous_1001_plus'], 200)
        self.assertEqual(summary['total_items'], 1200)
        self.assertTrue(summary['target_original_1000_reached'])
        self.assertFalse(summary['target_2000_reached'])
        self.assertEqual(summary['target_2000_aspirational_status'], 'CONCLUDED_AT_1200_QUALITATIVE_SATURATION')

    def test_no_false_c05_or_section_routing_mismatches_in_matrix(self):
        import nox_enhancements
        items = nox_matrix.load_matrix()['items']
        by_id = {it['id']: it for it in items}
        self.assertEqual(nox_enhancements.verify_no_false_c05_image_routing(items)['false_c05_items'], [])
        self.assertEqual(nox_enhancements.verify_no_section_level_routing_mismatch(items)['section_mismatches'], [])
        for bad_id in ('0376', '0409', '0771', '0775', '0813', '0842', '0845', '0995'):
            self.assertFalse(by_id[bad_id]['capability_group'].startswith('C05'), f'{bad_id} must not route to C05')
        self.assertTrue(by_id['0325']['capability_group'].startswith('C11'))
        self.assertTrue(by_id['0454']['capability_group'].startswith('C12'))
        self.assertTrue(by_id['0511']['capability_group'].startswith('C02'))

    def test_benchmark_executes_baseline_and_level2_scenarios(self):
        bench = nox_matrix.run_benchmark()
        self.assertEqual(bench['status'], 'PASS')
        l1 = bench['level1_synthetic_unit_comparison']
        self.assertGreater(l1['baseline_v1_0_3']['passed'], 0)
        self.assertGreater(l1['new_v1_2_0']['passed'], l1['baseline_v1_0_3']['passed'])
        self.assertEqual(l1['new_v1_2_0']['dev_passed'], '8/8')
        self.assertEqual(l1['new_v1_2_0']['blind_passed'], '8/8')
        self.assertEqual(bench['level2_http_functional_scenarios']['status'], 'PASS')

    def test_cli_subcommands_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            tp = Path(tmp)
            report_file = tp / 'report.json'
            report_file.write_text(json.dumps({
                'overall_status': 'PASS',
                'receipts': [{'check_id': 'c1', 'status': 'NOT_RUN', 'oracle': 'device', 'timestamp': '2026-11-21T00:00:00+00:00'}],
                'claims': [{'check_id': 'c1', 'statement': 'App works'}],
            }))
            # Unsupported claim report must exit 1
            proc_rep = subprocess.run([sys.executable, str(ROOT / 'scripts/nox.py'), 'report', str(report_file)], capture_output=True, text=True)
            self.assertEqual(proc_rep.returncode, 1)
            self.assertEqual(json.loads(proc_rep.stdout)['status'], 'FAIL')

            # matrix --id 0031 query must exit 0
            proc_mat = subprocess.run([sys.executable, str(ROOT / 'scripts/nox.py'), 'matrix', '--id', '0031'], capture_output=True, text=True)
            self.assertEqual(proc_mat.returncode, 0)
            self.assertEqual(json.loads(proc_mat.stdout)['item']['id'], '0031')

            # security-audit on repo root itself must exit 0
            proc_sec = subprocess.run([sys.executable, str(ROOT / 'scripts/nox.py'), 'security-audit', str(ROOT)], capture_output=True, text=True)
            self.assertEqual(proc_sec.returncode, 0)
            self.assertEqual(json.loads(proc_sec.stdout)['status'], 'PASS')

            # dry-run references sync must return NOT_RUN (exit 2)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(nox.main(['--dry-run', 'references', 'sync', 'keiyoushi']), 2)

    def test_verify_report_catches_missing_paths_and_accepts_valid_report(self):
        import nox_core
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'scripts').mkdir()
            (root / 'scripts/ok.py').write_text('pass\n')
            bad_rep = root / 'BAD.md'
            bad_rep.write_text('See `scripts/missing.py`.\n')
            self.assertEqual(nox_core.verify_report_claims(bad_rep, root)['status'], 'FAIL')

            good_rep = root / 'GOOD.md'
            good_rep.write_text('See `scripts/ok.py`.\n')
            self.assertEqual(nox_core.verify_report_claims(good_rep, root)['status'], 'PASS')

    def test_new_cli_commands_search_enhance_issues_deeplink_and_ui_plan(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(nox.main(['enhance', '--list']), 0)
            self.assertEqual(nox.main(['issues', 'verify-historical']), 0)
            # No device connected -> BLOCKED (exit code 2) cleanly without failing software contract
            self.assertIn(nox.main(['adb', 'ui-plan', '--package', 'app.mihon', '--source', 'Ex', '--query', 'Test']), {0, 2})

        with tempfile.TemporaryDirectory() as tmp:
            tp = Path(tmp)
            kt = tp / 'Ex.kt'
            kt.write_text('import keiyoushi.source.KeiSource\nclass Ex : KeiSource() { fun id(): Long = 1L }\n', encoding='utf-8')
            buf_diag = io.StringIO()
            with redirect_stdout(buf_diag):
                rc_diag = nox.main(['autofix-diagnose', str(tp), '--symptom', 'Google Drive 403 cover error'])
            self.assertEqual(rc_diag, 0)
            self.assertEqual(json.loads(buf_diag.getvalue())['ecosystem'], 'keiyoushi')

            buf_rc = io.StringIO()
            with redirect_stdout(buf_rc):
                rc_council = nox.main(['review-council', str(kt), '--enabled', '--ecosystem', 'keiyoushi'])
            self.assertEqual(rc_council, 0)
            self.assertEqual(json.loads(buf_rc.getvalue())['status'], 'PASS')

    def test_issue_10_global_flags_before_and_after_all_subcommands(self):
        # Issue #10 regression: `--json` (and other global flags) must work after AND before subcommands and nested subcommands.
        for cmd in (['doctor', '--json'], ['--json', 'doctor'], ['doctor'], ['doctor', '--technical']):
            proc = subprocess.run([sys.executable, str(ROOT / 'scripts/nox.py'), *cmd], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, msg=f'{cmd} failed: {proc.stderr}')
            data = json.loads(proc.stdout)
            self.assertIn('ecosystem_readiness', data)

        with tempfile.TemporaryDirectory() as tmp:
            import nox_scaffold
            tp = Path(tmp)
            (tp / 'Demo.kt').write_text('import keiyoushi.source.KeiSource\nclass Demo : KeiSource() { fun id(): Long = 42L }\n', encoding='utf-8')
            png = tp / 'sample.png'
            png.write_bytes(nox_scaffold._make_sample_png(800, 1200))
            out_dir = tp / 'sc_out'

            for cmd in (
                ['inspect', str(tp), '--json'],
                ['--json', 'inspect', str(tp)],
                ['security-audit', str(tp), '--json'],
                ['auto', 'Create manga extension for https://manga.example', '--dry-run', '--json'],
                ['--json', 'auto', 'Create manga extension for https://manga.example', '--dry-run'],
                ['lab', 'image', str(png), '--content-type', 'image/png', '--json'],
                ['--json', 'lab', 'image', str(png), '--content-type', 'image/png'],
                ['issues', 'verify-historical', '--json'],
                ['adb', 'doctor', '--json'],
                ['scaffold', 'keiyoushi', '--name', 'DemoExt', '--base-url', 'https://demo.example', '--lang', 'pt-BR', '--out', str(out_dir), '--json'],
            ):
                proc = subprocess.run([sys.executable, str(ROOT / 'scripts/nox.py'), *cmd], capture_output=True, text=True)
                self.assertIn(proc.returncode, {0, 2}, msg=f'{cmd} unexpected rc={proc.returncode} stderr={proc.stderr}')
                parsed = json.loads(proc.stdout)
                self.assertIsInstance(parsed, dict)

            self.assertTrue((out_dir / 'src').exists() or any(out_dir.rglob('*')))

    def test_auto_workflows_adaptive_output_and_loop_detection(self):
        import nox_core
        import nox_scaffold

        buf_beg = io.StringIO()
        with redirect_stdout(buf_beg):
            rc_beg = nox.main(['auto', 'Create manga extension for https://manga.example', '--dry-run'])
        self.assertIn(rc_beg, {0, 2})
        beg_data = json.loads(buf_beg.getvalue())
        self.assertEqual(beg_data['mode'], 'beginner')
        self.assertNotIn('technical_details', beg_data)
        self.assertTrue(Path(beg_data['diagnostics_file']).is_file())
        self.assertIn('user_message', beg_data)
        self.assertIn('next_step', beg_data)
        self.assertFalse(beg_data['agent_continuation']['task_complete'])

        buf_tech = io.StringIO()
        with redirect_stdout(buf_tech):
            rc_tech = nox.main(['auto', 'Create manga extension for https://manga.example', '--dry-run', '--technical'])
        self.assertIn(rc_tech, {0, 2})
        tech_data = json.loads(buf_tech.getvalue())
        self.assertEqual(tech_data['mode'], 'technical')
        self.assertIn('parsed_request', tech_data)
        self.assertIn('reference_snapshot', tech_data)
        self.assertEqual(tech_data['status'], 'INCONCLUSIVE')

        with tempfile.TemporaryDirectory() as tmp:
            tp = Path(tmp)
            out_dir = tp / 'created'
            created = nox_scaffold.auto_create_extension(
                'Crie extensao anime para https://animes.example',
                output_dir=out_dir,
                ui_lang='pt-BR',
            )
            # Unreachable .example site must remain INCONCLUSIVE rather than falsely claiming PASS for a bare template
            self.assertEqual(created['status'], 'INCONCLUSIVE')
            self.assertEqual(created['ecosystem'], 'yuzono')
            self.assertNotIn('technical_details', created)
            self.assertTrue(created['agent_continuation']['must_continue_automatically'])
            diag_loaded = json.loads(Path(created['diagnostics_file']).read_text(encoding='utf-8'))
            self.assertFalse(diag_loaded['optional_adb_guide']['required'])

            att_file = tp / 'attempts.json'
            att_file.write_text(json.dumps([
                {'step': 1, 'error': 'HTTP 403 Cloudflare', 'selector': 'div.list', 'hypothesis': 'change css selector'},
                {'step': 2, 'error': 'HTTP 403 Cloudflare', 'selector': 'div.list', 'hypothesis': 'change css selector'},
            ]), encoding='utf-8')
            buf_fix = io.StringIO()
            with redirect_stdout(buf_fix):
                rc_fix = nox.main(['auto-fix', str(out_dir), '--symptom', 'HTTP 403 Cloudflare', '--attempts-json', str(att_file), '--technical'])
            self.assertIn(rc_fix, {0, 2})
            fix_data = json.loads(buf_fix.getvalue())
            self.assertTrue(fix_data['loop_detection']['loop_detected'])
            self.assertEqual(fix_data['loop_detection']['stagnation_category'], 'network_or_protection')
            self.assertFalse(fix_data['optional_adb_guide']['required'])
            self.assertFalse(fix_data['code_modified'])

        loop_ok = nox_core.detect_investigation_loop([{'error': '404', 'selector': 'a', 'hypothesis': 'h1'}])
        self.assertFalse(loop_ok['loop_detected'])


if __name__ == '__main__':
    unittest.main()
