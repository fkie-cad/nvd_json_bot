from pathlib import Path
from tempfile import TemporaryDirectory

from util import cve_paths


def test_get_cve_json_path():

    test_cve_id: str = "CVE-2023-1234567"

    with TemporaryDirectory() as root:
        expected: Path = Path(root) / "CVE-2023" / "CVE-2023-12345xx" / "CVE-2023-1234567.json"
        assert cve_paths.get_cve_json_path(test_cve_id, path_prefix=root) == expected
