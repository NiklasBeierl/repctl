import json
import logging
from copy import deepcopy
from glob import glob
from pathlib import Path
from typing import TypedDict, cast

import yaml

from repctl.exceptions import RepctlException, SnippetParsingException

LOGGER = logging.getLogger(__name__)
FM_BOUNDARY = "---"


class SnippetData(TypedDict):
    lang: str
    isMain: bool
    contentField: str
    templateId: str
    tags: list[str]
    sysReptorFields: dict[str, str]
    annotations: dict[str, str]


def get_content_field(data: SnippetData) -> str:
    content_field = data["contentField"]
    if content_field not in data["sysReptorFields"]:
        raise RepctlException("Snippet data does not contain content field.")

    return data["sysReptorFields"][content_field]  # type: ignore


def set_content_field(data: SnippetData, content: str) -> None:
    content_field = data["contentField"]

    data["sysReptorFields"][content_field] = content  # type: ignore


def read_snippet(path: Path) -> SnippetData:
    with open(path) as f:
        lines = iter(f.readlines())

    line = next(lines)
    if line.strip() != FM_BOUNDARY:
        raise SnippetParsingException(
            f"Snippet file {path} does not start with frontmatter"
        )
    frontmatter_lines: list[str] = []
    try:
        while (line := next(lines)).strip() != FM_BOUNDARY:
            frontmatter_lines.append(line)
    except StopIteration:
        raise SnippetParsingException(f"Frontmatter of {path} is not terminated")

    try:
        frontmatter = yaml.safe_load("".join(frontmatter_lines))
    except json.JSONDecodeError:
        raise SnippetParsingException(f"Frontmatter of {path} is not JSON")

    content_lines = list(lines)

    data = cast(SnippetData, frontmatter)
    set_content_field(data, "".join(content_lines))
    return data


def write_snippet(path: Path, data: SnippetData) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    data_copy = deepcopy(data)
    content_field = data["contentField"]
    content = data["sysReptorFields"][content_field]  # type: ignore
    del data_copy["sysReptorFields"][content_field]

    with open(path, "w") as f:
        f.write(f"{FM_BOUNDARY}\n{yaml.dump(data_copy)}{FM_BOUNDARY}\n")
        f.write(content)


def get_snippets(
    snippets_dir: Path,
) -> dict[str, SnippetData]:
    pattern = f"{snippets_dir}/**/*.md"
    results = {}
    for p in glob(pattern):
        path = Path(p)
        data = read_snippet(Path(p))
        snippet_suffix = str(path.with_suffix("").relative_to(snippets_dir))
        results[snippet_suffix] = data
    return results
