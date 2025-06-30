import logging
import os
from argparse import ArgumentParser, Namespace
from collections import defaultdict
from pathlib import Path

from repctl.exceptions import InvalidScubaReport, RepctlException
from repctl.reporting.scuba import read_report_file
from repctl.snippets import (
    get_snippets,
    read_snippet,
)
from repctl.sysreptor import (
    FindingTemplate,
    FindingTemplateTranslation,
    ReptorSession,
    make_template_id,
    parse_project_url,
)
from repctl.utils import setup_logging

LOGGER = logging.getLogger("repctl")

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    ...

CONTENT_PATH = Path(__file__).parent / "../content"


def load_templates(args: Namespace) -> int:
    if not (api_key := args.api_key or os.getenv("REPTOR_KEY")):
        LOGGER.error("No Reptor API key provided, pass --api-key or set REPTOR_KEY")
        return 1

    if args.input.is_file():
        all_snippets = {
            args.input.name.with_suffix(""): read_snippet(args.input)
        }
    else:
        all_snippets = get_snippets(args.input)


    main_found : set[str] = set()
    langs_found : defaultdict[str, set[str]] = defaultdict(set)
    templates: dict[str, FindingTemplate] = {}

    for snippet in all_snippets.values():
        template_id = snippet["templateId"]
        id_value = make_template_id(template_id)
        lang = snippet["lang"]

        if snippet["isMain"]:
            if id_value in main_found:
                LOGGER.error(f"Found multiple main translations for {template_id}, aborting.")
                return 1
            else:
                main_found.add(id_value)

        if lang in langs_found[id_value]:
            LOGGER.error(f"Found multiple {lang} translations for {template_id}, aborting.")
            return 1
        langs_found[id_value].add(lang)

        translation: FindingTemplateTranslation = dict(
            id=None,
            language=lang,
            is_main=snippet["isMain"],
            data={
                **snippet["sysReptorFields"],
                "_my_reptor_identifier": id_value,
            },
        )

        template: FindingTemplate
        if template_id not in templates:
            template = templates[id_value] = dict(
                id = None,
                details = None,
                translations = [],
                tags=list(set(snippet["tags"])),
            )

        else:
            template = templates[id_value]

        template["translations"].append(translation)

    session = ReptorSession(base_url=args.reptorurl, api_key=api_key)
    for id_value, template in templates.items():
        session.templates.search_and_upsert(template, search=id_value)
    return 0


def reptor_report(args: Namespace) -> int:
    try:
        results = read_report_file(args.input)
    except InvalidScubaReport as e:
        print(e.msg)
        return 1

    if not (api_key := args.api_key or os.getenv("REPTOR_KEY")):
        LOGGER.error("No Reptor API key provided, pass --api-key or set REPTOR_KEY")
        return 1

    try:
        base_url, project_id = parse_project_url(args.project_url)
    except RepctlException as e:
        print(e.msg)
        return 1

    LOGGER.warning(f"Importing findings to SysReptor project {project_id}")

    session = ReptorSession(base_url=base_url, api_key=api_key)

    # TODO: Filter N/A findings and groups that only contain N/A findings
    for product, groups in results.items():
        for group in groups:
            # Add pseudo-finding for policyGroup
            group_id = group["GroupNumber"]
            template_id = make_template_id(f"{product.lower()}-{group_id}")
            template = session.templates.find_one(template_id)
            session.findings.create_from_template(
                project_id=project_id,
                template_id=template["id"],
                template_language=args.lang,
            )

            # Add actual findings
            for control in group["Controls"]:
                policy_id = control["ControlID"]
                template_id = make_template_id(policy_id)
                template = session.templates.find_one(template_id)
                finding = session.findings.create_from_template(
                    project_id=project_id,
                    template_id=template["id"],
                    template_language=args.lang,
                )
                finding["data"] = {
                    **finding["data"],
                    "criticality": control["Criticality"],
                    "result": control["Result"],
                    "details": control["Details"],
                }
                session.findings.update(
                    project_id=project_id,
                    finding_id=finding["id"],
                    finding=finding,
                )
                LOGGER.warning(f"Added finding {policy_id} ({finding['id']})")
    return 0


def main_cli() -> int:
    setup_logging()
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(required=True)

    # TODO: Break this up for different reporting tools
    reptor_report_parser = subparsers.add_parser("scuba-report")
    reptor_report_parser.set_defaults(func=reptor_report)
    reptor_report_parser.add_argument(
        "--lang",
        type=str,
        help="Code of language to use for templates, default: de-DE",
        default="de-DE",
    )
    reptor_report_parser.add_argument(
        "--api-key",
        type=str,
        help="Sysreptor API Key, may also be passed as env var: REPTOR_KEY",
    )
    reptor_report_parser.add_argument(
        "input", type=Path, help="Input file: ScubaResults_<id>.json"
    )
    reptor_report_parser.add_argument(
        "project_url",
        type=str,
        help="URL of the project on your sysreptor instance.",
    )

    load_templates_parser = subparsers.add_parser("load-templates")
    load_templates_parser.set_defaults(func=load_templates)
    load_templates_parser.add_argument(
        "--api-key",
        type=str,
        help="Sysreptor API Key, may also be passed as env var: REPTOR_KEY",
    )
    load_templates_parser.add_argument(
        "reptorurl",
        type=str,
        help="BaseUrl of SysReptor Instance, e.g.: https://sysreptor.example.com",
    )
    load_templates_parser.add_argument(
        "input",
        type=Path,
        help="Template snippet or dir containing snippets."
    )

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    exit(main_cli())
