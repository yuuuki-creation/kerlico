"""检查生产 Error、I/O 与服务失败静态详情的英译目录；不把未知项算作已翻译。"""
import argparse
import json
from pathlib import Path
import re
from collections import Counter

ROOT = Path(__file__).resolve().parent.parent
LITERAL = r'"((?:[^"\\]|\\.)*)"'
ERROR = re.compile(r'(?:Error|ServiceFailure)::(?:Config|Protocol|Unsupported|General)\(\s*' + LITERAL)
IO_ERROR = re.compile(r'(?:(?:io::)?Error::new|ServiceFailure::Io)\(\s*[^,]+?,\s*' + LITERAL + r'|(?:io::)?Error::other\(\s*' + LITERAL)
CONFIG_FORMAT = re.compile(r'Error::Config\(\s*format!\(')
CONFIG_TEMPLATE = re.compile(CONFIG_FORMAT.pattern + r'\s*' + LITERAL)
ENTRY = re.compile(r'\(\s*' + LITERAL + r'\s*,\s*' + LITERAL + r'\s*,?\s*\)')
LEXICAL = re.compile(r'//[^\n]*|/\*.*?\*/|(?:br|r)(?P<hashes>\#*)".*?"(?P=hashes)|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\\n]|\\.)\'', re.S)


def production_source(source):
    """移除 cfg(test) 单项，保留位于测试声明后的生产代码。"""
    masked = LEXICAL.sub(lambda match: ' ' * len(match[0]), source)
    excluded = []
    for match in re.finditer(r'#\[cfg\(test\)\]', masked):
        if excluded and match.start() < excluded[-1][1]:
            continue
        depth = 0
        end = len(source)
        for position in range(match.end(), len(masked)):
            character = masked[position]
            if character in '([{':
                depth += 1
            elif character in ')]}':
                depth -= 1
                if character == '}' and depth == 0:
                    end = position + 1
                    break
            elif character in ';,' and depth == 0:
                end = position + 1
                break
        excluded.append((match.start(), end))
    for start, end in reversed(excluded):
        source = source[:start] + ' ' * (end - start) + source[end:]
    return source


def inventory(scope, protocols=()):
    catalogs = [ROOT / 'crates/core-api/src/locale.rs', *sorted((ROOT / 'crates/core-api/src/locale').glob('*.rs'))]
    entries = [entry for path in catalogs for entry in ENTRY.findall(path.read_text(encoding='utf-8'))]
    catalog = dict(entries)
    duplicates = sorted(message for message, count in Counter(message for message, _ in entries).items() if count > 1)
    invalid_translations = [message for message, english in entries if not english or any('\u3400' <= character <= '\u9fff' for character in english)]
    directories = ['crates/core-api/src', 'crates/config/src', 'crates/net/src', 'apps/kerlico/src']
    if scope == 'all':
        directories = ['apps/kerlico/src', *[path.relative_to(ROOT).as_posix() for path in (ROOT / 'crates').glob('*/src')]]
    if protocols:
        directories = []
        for protocol in protocols:
            if not re.fullmatch('[a-z0-9-]+', protocol):
                raise ValueError('invalid protocol identifier')
            directory = ROOT / 'crates' / ('protocol-' + protocol) / 'src'
            if not directory.is_dir():
                raise ValueError('unknown protocol identifier')
            directories.append(directory.relative_to(ROOT).as_posix())
    found = {}
    dynamic = []
    translated_templates = []
    for directory in directories:
        for path in sorted((ROOT / directory).rglob('*.rs')):
            relative = path.relative_to(ROOT).as_posix()
            if 'vendor' in path.parts or 'tests' in path.relative_to(ROOT).parts or path.name == 'locale.rs' or re.search(r'(?:^|_)(?:tests?|fixture)\b', path.stem):
                continue
            source = production_source(path.read_text(encoding='utf-8'))
            details = [match[1] for match in ERROR.finditer(source)]
            details.extend(next(value for value in match.groups() if value is not None) for match in IO_ERROR.finditer(source))
            for message in details:
                if any('\u3400' <= character <= '\u9fff' for character in message):
                    found.setdefault(message, []).append(relative)
            templates = {match.start(): match[1] for match in CONFIG_TEMPLATE.finditer(source)}
            for match in CONFIG_FORMAT.finditer(source):
                template = templates.get(match.start())
                if template is None:
                    dynamic.append(relative)
                    continue
                chunks = re.split(r'\{(?:[a-zA-Z_][a-zA-Z0-9_]*|[0-9]*)\}', template)
                chinese = [chunk for chunk in chunks if any('\u3400' <= character <= '\u9fff' for character in chunk)]
                for message in chinese:
                    found.setdefault(message, []).append(relative)
                if not chinese or any(message not in catalog for message in chinese):
                    dynamic.append(relative)
                else:
                    translated_templates.append({'file': relative, 'template': template})
    missing = [{'message': message, 'files': files} for message, files in sorted(found.items()) if message not in catalog]
    return {'scope': scope, 'protocols': list(protocols), 'method': 'Error, io::Error and ServiceFailure literal constructors with cfg(test) items excluded',
            'static_details': len(found), 'translated_details': len(found) - len(missing),
            'catalog_entries': len(catalog), 'missing': missing, 'dynamic_config_templates': dynamic,
            'translated_config_templates': translated_templates,
            'duplicate_keys': duplicates, 'invalid_translations': invalid_translations}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', choices=['boundary', 'all'], default='boundary')
    parser.add_argument('--protocol', action='append', default=[])
    args = parser.parse_args()
    result = inventory(args.scope, args.protocol)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(bool(result['missing'] or result['dynamic_config_templates'] or result['duplicate_keys'] or result['invalid_translations']))
