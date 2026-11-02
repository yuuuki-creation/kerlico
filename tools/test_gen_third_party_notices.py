import contextlib
import io
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gen_third_party_notices as notices

APACHE = "Apache License\nVersion 2.0, January 2004\nCopyright [yyyy] [name of copyright owner]"
UNIDENTIFIED = "Use of this package is governed by its own terms. " * 5


class NoticesTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = pathlib.Path(directory.name)

    def package(self, name, license, files=None, authors=("Synthetic Author",)):
        root = self.root / name
        root.mkdir()
        (root / "Cargo.toml").write_text("")
        for relative, text in (files or {}).items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return {"name": name, "version": "1.0.0", "license": license, "license_file": None,
                "manifest_path": str(root / "Cargo.toml"), "authors": list(authors),
                "repository": f"https://example.invalid/{name}"}

    def run_main(self, *packages):
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = notices.main(list(packages))
        return code, output.getvalue(), errors.getvalue()

    def test_missing_file_is_filled_from_the_template_with_authors_and_repository(self):
        code, output, _ = self.run_main(self.package("plain", "BSD-3-Clause"))
        self.assertEqual(code, 0)
        self.assertIn("Copyright (c) Synthetic Author", output)
        self.assertIn("Neither the name of the copyright holder", output)
        self.assertIn("https://example.invalid/plain", output)

    def test_package_without_authors_still_names_a_holder(self):
        _, output, _ = self.run_main(self.package("nameless", "ISC", authors=()))
        self.assertIn("Copyright (c) The nameless authors", output)

    def test_other_licenses_reuse_unmodified_text_from_the_graph(self):
        donor = self.package("donor", "Apache-2.0", {"LICENSE-APACHE": APACHE})
        code, output, _ = self.run_main(donor, self.package("borrower", "Apache-2.0"))
        self.assertEqual(code, 0)
        self.assertIn("borrower 1.0.0 (Apache-2.0 standard text", output)
        self.assertEqual(output.count("Copyright [yyyy]"), 1)

    def test_license_without_text_anywhere_fails(self):
        code, _, errors = self.run_main(self.package("lonely", "Apache-2.0"))
        self.assertEqual(code, 1)
        self.assertIn("lonely 1.0.0", errors)

    def test_one_satisfied_alternative_is_enough(self):
        package = self.package("either", "MIT OR Apache-2.0", {"LICENSE-MIT": notices.MIT})
        code, output, _ = self.run_main(package)
        self.assertEqual(code, 0)
        self.assertNotIn("standard text", output)

    def test_every_and_term_needs_text(self):
        package = self.package("both", "(MIT OR Apache-2.0) AND Unicode-3.0", {"LICENSE-MIT": notices.MIT})
        code, _, errors = self.run_main(package)
        self.assertEqual(code, 1)
        self.assertIn("both 1.0.0", errors)

    def test_licenses_directory_counts_but_vendored_upstream_does_not(self):
        code, output, _ = self.run_main(
            self.package("reuse", "MIT", {"LICENSES/MIT.txt": notices.MIT.replace("{holders}", "Reuse Holder")}),
            self.package("vendoring", "MIT", {"src/upstream/LICENSE": "Upstream terms."}),
        )
        self.assertEqual(code, 0)
        self.assertIn("reuse 1.0.0 (LICENSES/MIT.txt)", output)
        self.assertNotIn("reuse 1.0.0 (MIT standard text", output)
        self.assertIn("vendoring 1.0.0 (src/upstream/LICENSE)", output)
        self.assertIn("vendoring 1.0.0 (MIT standard text", output)

    def test_unidentified_license_file_is_kept_without_a_template(self):
        code, output, _ = self.run_main(self.package("custom", "MIT", {"LICENSE": UNIDENTIFIED}))
        self.assertEqual(code, 0)
        self.assertIn(UNIDENTIFIED.strip(), output)
        self.assertNotIn("standard text", output)

    def test_one_line_pointer_is_not_license_text(self):
        code, output, _ = self.run_main(self.package("pointer", "MIT", {"LICENSE": "MIT"}))
        self.assertEqual(code, 0)
        self.assertIn("pointer 1.0.0 (MIT standard text", output)

    def test_mpl_text_mentioning_lgpl_stays_reusable(self):
        mpl = "Mozilla Public License Version 2.0\nSecondary License means the GNU Lesser General Public License, Version 2.1"
        code, output, _ = self.run_main(
            self.package("donor", "MPL-2.0", {"LICENSE": mpl}),
            self.package("borrower", "MPL-2.0"),
        )
        self.assertEqual(code, 0)
        self.assertIn("borrower 1.0.0 (MPL-2.0 standard text", output)

    def test_expression_forms(self):
        self.assertEqual(notices.parse_expression("MIT/Apache-2.0"), ("or", ["MIT", "Apache-2.0"]))
        self.assertEqual(notices.parse_expression("Apache-2.0 / MIT"), ("or", ["Apache-2.0", "MIT"]))
        self.assertEqual(
            notices.parse_expression("Apache-2.0 WITH LLVM-exception OR MIT"),
            ("or", ["Apache-2.0", "MIT"]))
        self.assertEqual(
            notices.parse_expression("(MIT OR Apache-2.0) AND Unicode-3.0"),
            ("and", [("or", ["MIT", "Apache-2.0"]), "Unicode-3.0"]))

    def test_package_without_any_license_field_needs_a_file(self):
        code, _, errors = self.run_main(self.package("bare", None))
        self.assertEqual(code, 1)
        self.assertIn("bare 1.0.0", errors)


if __name__ == "__main__":
    unittest.main()
