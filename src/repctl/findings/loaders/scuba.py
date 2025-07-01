__all__ = ["ScubaFindingLoader"]

import json
from argparse import ArgumentParser, Namespace
from logging import getLogger
from pathlib import Path
from typing import TypedDict

from repctl.exceptions import InvalidScubaReport
from repctl.findings import FindingLoader

LOGGER = getLogger(__name__)


class ScubaResultControl(TypedDict):
    # The results file actually uses "Control ID" as key
    # We rename this in read_report_file
    ControlID: str
    Result: str
    Criticality: str
    Details: str


class ScubaResultGroup(TypedDict):
    GroupNumber: str
    Controls: list[ScubaResultControl]


ScubaResults = dict[str, list[ScubaResultGroup]]


def read_report_file(file: str) -> ScubaResults:
    with open(file, "r", encoding="utf-8-sig") as in_file:
        results = json.load(in_file)
    if isinstance(results, list):
        raise InvalidScubaReport(
            "The input file you passed has an unexpected JSON-Structure. "
            "Perhaps you passed TestResults.json instead of ScubaResults_<id>.json?"
        )
    elif "Results" not in results:
        raise InvalidScubaReport(
            "The input file you passed has an unexpected JSON-Structure. "
            "There is no key 'Results'."
        )

    results = results["Results"]
    for groups in results.values():
        for group in groups:
            for control in group["Controls"]:
                control["ControlID"] = control["Control ID"]
                del control["Control ID"]

    return results


class ScubaFindingLoader(FindingLoader):
    name = "scubagear"

    @classmethod
    def configure_parser(cls, parser: ArgumentParser):
        parser.add_argument(
            "--lang",
            type=str,
            help="Language code to use for templates, default: de-DE",
            default="de-DE",
        )
        parser.add_argument(
            "input", type=Path, help="Input file: ScubaResults_<id>.json"
        )

    def __call__(self, args: Namespace) -> int:
        try:
            results = read_report_file(args.input)
        except InvalidScubaReport as e:
            LOGGER.error(e.msg)
            return 1

        for product, groups in results.items():
            for group in groups:
                # Add pseudo-finding for policyGroup
                group_id = group["GroupNumber"]
                template_id = self.get_template_id(f"{product.lower()}-{group_id}")
                group_template = self.session.templates.find_one(template_id)
                if group_template is not None:
                    self.session.findings.create_from_template(
                        project_id=self.project_id,
                        template_id=group_template["id"],
                        template_language=args.lang,
                    )

                # Add findings for policies
                for control in group["Controls"]:
                    policy_id = control["ControlID"]
                    template_id = self.get_template_id(policy_id)
                    template = self.session.templates.find_one(template_id)
                    if template is None:
                        LOGGER.error(f"Could not find template {template_id}")
                        return 1
                    finding = self.session.findings.create_from_template(
                        project_id=self.project_id,
                        template_id=template["id"],
                        template_language=args.lang,
                    )
                    finding["data"] = {
                        **finding["data"],
                        "criticality": control["Criticality"],
                        "result": control["Result"],
                        "details": control["Details"],
                    }
                    self.session.findings.update(
                        project_id=self.project_id,
                        finding=finding,
                    )
                    LOGGER.info(f"Added finding {policy_id} ({finding['id']})")
        return 0
