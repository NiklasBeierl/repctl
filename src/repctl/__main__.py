#!/usr/bin/env python
import logging
from argparse import ArgumentParser, Namespace
from collections import defaultdict
from functools import partial
from pathlib import Path
from typing import Type

from dotenv import load_dotenv

from repctl.exceptions import RepctlException
from repctl.findings import FindingLoader
from repctl.findings.loaders.scuba import ScubaFindingLoader
from repctl.snippets import (
    SnippetData,
    get_snippets,
    read_snippet,
)
from repctl.sysreptor import (
    NewFindingTemplate,
    NewFindingTemplateTranslation,
    ReptorSession,
    make_template_id,
    parse_project_url,
)
from repctl.utils import get_api_key, setup_logging

LOGGER = logging.getLogger("repctl")
ID_VALUE_FIELD_NAME = "repctlTemplateId"
CONF_FILE_PATH = Path.home() / ".config" / "repctl.env"
LOCAL_DOTENV_PATH = Path(".env")


def load_templates(args: Namespace) -> int:
    if not (api_key := get_api_key(args)):
        return 1

    all_snippets: dict[str, SnippetData]
    if args.input.is_file():
        all_snippets = {args.input.name.with_suffix(""): read_snippet(args.input)}
    else:
        all_snippets = get_snippets(args.input)

    main_found: set[str] = set()
    langs_found: defaultdict[str, set[str]] = defaultdict(set)
    templates: dict[str, NewFindingTemplate] = {}

    for snippet in all_snippets.values():
        template_id = snippet["templateId"]
        id_value = make_template_id(template_id)
        lang = snippet["lang"]

        if snippet["isMain"]:
            if id_value in main_found:
                LOGGER.error(
                    f"Found multiple main translations for {template_id}, aborting."
                )
                return 1
            else:
                main_found.add(id_value)

        if lang in langs_found[id_value]:
            LOGGER.error(
                f"Found multiple {lang} translations for {template_id}, aborting."
            )
            return 1
        langs_found[id_value].add(lang)

        translation: NewFindingTemplateTranslation = dict(
            language=lang,
            is_main=snippet["isMain"],
            data={
                **snippet["sysReptorFields"],
                ID_VALUE_FIELD_NAME: id_value,
            },
        )

        template: NewFindingTemplate
        if template_id not in templates:
            template = templates[id_value] = dict(
                translations=[],
                tags=list(set(snippet["tags"])),
            )

        else:
            template = templates[id_value]

        template["translations"].append(translation)

    session = ReptorSession(base_url=args.reptorurl, api_key=api_key)
    for id_value, template in templates.items():
        session.templates.search_and_upsert(template, search=id_value)
    return 0


def run_finding_loader(loader_class: Type[FindingLoader], args: Namespace) -> int:
    if not (api_key := get_api_key(args)):
        return 1

    try:
        base_url, project_id = parse_project_url(args.project_url)
    except RepctlException as e:
        print(e.msg)
        return 1

    LOGGER.info(
        f"Importing findings to SysReptor project {project_id} "
        f"with loader {loader_class.name}"
    )

    session = ReptorSession(base_url=base_url, api_key=api_key)
    loader = loader_class(session=session, project_id=project_id)
    return loader(args)


def main_cli() -> int:
    setup_logging()

    parser = ArgumentParser()
    parser.add_argument(
        "--api-key",
        type=str,
        help="SysReptor API Key, may also be passed as env var: REPTOR_KEY",
    )
    subparsers = parser.add_subparsers(required=True)

    load_templates_parser = subparsers.add_parser("load-templates")
    load_templates_parser.set_defaults(func=load_templates)
    load_templates_parser.add_argument(
        "reptorurl",
        type=str,
        help="BaseUrl of SysReptor Instance, e.g.: https://sysreptor.example.com",
    )
    load_templates_parser.add_argument(
        "input",
        type=Path,
        help="Snippet file or directory containing snippets "
        "(searched recursively for .md files)",
    )

    load_findings_parser = subparsers.add_parser("load-findings")
    loader_subparsers = load_findings_parser.add_subparsers(required=True)
    for loader in [ScubaFindingLoader]:
        loader_parser = loader_subparsers.add_parser(loader.name)
        loader_parser.set_defaults(func=partial(run_finding_loader, loader))
        loader_parser.add_argument(
            "project_url",
            type=str,
            help="URL of the project on your SysReptor instance. "
            "(Simply copy it from your browser!)",
        )
        loader.configure_parser(loader_parser)

    args = parser.parse_args()

    if CONF_FILE_PATH.exists():
        LOGGER.info(f"Loading env vars from {CONF_FILE_PATH}")
        load_dotenv(CONF_FILE_PATH)

    if LOCAL_DOTENV_PATH.exists():
        LOGGER.info(f"Loading env vars from {LOCAL_DOTENV_PATH}")
        load_dotenv()

    return args.func(args)


if __name__ == "__main__":
    exit(main_cli())
