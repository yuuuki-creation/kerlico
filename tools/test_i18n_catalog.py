"""目录覆盖门的边界回归；仅在海外 worker 执行。"""
import importlib.util
from pathlib import Path
import tempfile
import unittest


class CatalogBoundaryTests(unittest.TestCase):
    def setUp(self):
        specification = importlib.util.spec_from_file_location('catalog', Path(__file__).with_name('check_i18n.py'))
        self.catalog = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(self.catalog)
        self.directory = tempfile.TemporaryDirectory(prefix='kerlico-i18n-gate-')
        self.addCleanup(self.directory.cleanup)
        self.catalog.ROOT = Path(self.directory.name)
        self.write('crates/core-api/src/locale.rs', '')

    def write(self, name, contents):
        path = self.catalog.ROOT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding='utf-8')

    def test_external_test_declaration_keeps_later_production_diagnostics(self):
        self.write('apps/kerlico/src/main.rs', '''
#[cfg(test)] mod tests;
fn production() { Error::Protocol("真实生产错误"); }
#[cfg(test)] mod inline { fn test() { Error::Protocol("测试错误"); let _ = "}"; } }
fn later() { Error::Config("后续生产错误".into()); }
''')
        result = self.catalog.inventory('all')
        self.assertEqual({row['message'] for row in result['missing']}, {'真实生产错误', '后续生产错误'})

    def test_io_service_and_external_error_details_require_concrete_translations(self):
        self.write('apps/kerlico/src/main.rs', '''
io::Error::new(error.kind(), "自定义读取错误");
io::Error::other("自定义写入错误");
ServiceFailure::Protocol("服务错误");
ServiceFailure::Io(io::ErrorKind::ConnectionReset, "服务读写错误");
rustls::Error::General("握手错误".into());
''')
        self.assertEqual(self.catalog.inventory('all')['static_details'], 5)
        self.write('crates/core-api/src/locale.rs', '''
const DATA: &[(&str, &str)] = &[("自定义读取错误", "Custom read failed")];
''')
        result = self.catalog.inventory('all')
        self.assertEqual(result['translated_details'], 1)
        self.assertEqual(len(result['missing']), 4)

    def test_duplicate_invalid_and_dynamic_entries_cannot_pass_the_gate(self):
        self.write('crates/core-api/src/locale.rs', '''
const DATA: &[(&str, &str)] = &[("重复错误", "First"), ("重复错误", "Second"), ("残留错误", "未翻译")];
''')
        self.write('apps/kerlico/src/main.rs', 'Error::Config(format!("动态错误 {value}"));')
        result = self.catalog.inventory('all')
        self.assertEqual(result['duplicate_keys'], ['重复错误'])
        self.assertEqual(result['invalid_translations'], ['残留错误'])
        self.assertEqual(result['dynamic_config_templates'], ['apps/kerlico/src/main.rs'])

    def test_nested_test_modules_are_excluded_but_neighboring_production_is_not(self):
        self.write('crates/protocol-demo/src/tests/runtime.rs', 'Error::Protocol("仅测试诊断");')
        self.write('crates/protocol-demo/src/runtime.rs', 'Error::Protocol("真实运行诊断");')
        result = self.catalog.inventory('all')
        self.assertEqual([row['message'] for row in result['missing']], ['真实运行诊断'])

    def test_formatted_details_require_every_chinese_literal_segment(self):
        self.write('apps/kerlico/src/main.rs', 'Error::Config(format!("注册状态{status}；保留意图"));')
        self.write('crates/core-api/src/locale.rs', 'const DATA: &[(&str, &str)] = &[("注册状态", "Registration status ")];')
        self.assertEqual(self.catalog.inventory('all')['dynamic_config_templates'], ['apps/kerlico/src/main.rs'])
        self.write('crates/core-api/src/locale.rs', 'const DATA: &[(&str, &str)] = &[("注册状态", "Registration status "), ("；保留意图", "; intent retained")];')
        result = self.catalog.inventory('all')
        self.assertEqual(result['dynamic_config_templates'], [])
        self.assertEqual(len(result['translated_config_templates']), 1)


if __name__ == '__main__':
    unittest.main()
