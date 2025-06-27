__all__ = ["read_report_file"]
import json
from logging import getLogger
from typing import TypedDict

from repctl.exceptions import InvalidScubaReport

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
