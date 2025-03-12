from pathlib import Path


def get_bucket_for_cve_id(cve_id: str, path_prefix: str = ".") -> Path:
    year: str
    num: str
    _, year, num = cve_id.split("-")
    masked_number: str = f"{num[:-2]}xx"
    bucket: Path = Path(f"{path_prefix}/CVE-{year}/CVE-{year}-{masked_number}")
    return bucket


def get_cve_json_path(cve_id: str, path_prefix: str = ".") -> Path:
    bucket: Path = get_bucket_for_cve_id(cve_id=cve_id, path_prefix=path_prefix)
    return bucket / Path(f"{cve_id}.json")
