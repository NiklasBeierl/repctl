import logging
import os
from argparse import ArgumentParser, Namespace
from pathlib import Path

from repctl.exceptions import InvalidScubaReport, RepctlException
from repctl.reporting.scuba import read_report_file
from repctl.snippets import (
    get_snippets,
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

    session = ReptorSession(base_url=args.reptorurl, api_key=api_key)

    # TODO: Properly collect snippets into templates based on templateId and language
    en_snippets = get_snippets(translations=False)
    de_snippets = get_snippets(translations=True)

    for name, en_snippet in en_snippets.items():
        de_snippet = de_snippets[name]
        id_value = make_template_id(en_snippet["templateId"])
        de_trans: FindingTemplateTranslation = dict(
            id=None,
            language="de-DE",
            is_main=True,
            data={
                **de_snippet["sysReptorFields"],
                "_my_reptor_identifier": id_value,
            },
        )
        en_trans: FindingTemplateTranslation = dict(
            id=None,
            language="en-US",
            is_main=False,
            data={
                **en_snippet["sysReptorFields"],
                "_my_reptor_identifier": id_value,
            },
        )
        template: FindingTemplate = dict(
            id=None,
            details=None,
            translations=[en_trans, de_trans],
            tags=en_snippet["tags"],
        )
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
        "input", type=Path, help="Input file: ScubaResults_<id>.json"
    )
    reptor_report_parser.add_argument(
        "project_url",
        type=str,
        help="URL of the project on your sysreptor instance.",
    )
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

    load_templates_parser = subparsers.add_parser("load-templates")
    load_templates_parser.set_defaults(func=load_templates)
    load_templates_parser.add_argument(
        "reptorurl",
        type=str,
        help="BaseUrl of SysReptor Instance, e.g.: https://sysreptor.example.com",
    )
    load_templates_parser.add_argument(
        "--api-key",
        type=str,
        help="Sysreptor API Key, may also be passed as env var: REPTOR_KEY",
    )

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    exit(main_cli())
