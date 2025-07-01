import logging
import re
from abc import ABC
from hashlib import sha1
from typing import Any, Generator, Generic, TypedDict, TypeVar, cast
from urllib.parse import urlparse, urlunparse

from requests_toolbelt.sessions import BaseUrlSession

from repctl.exceptions import RepctlException

# Used to indicate that a REST field is a URL
URL = str

LOGGER = logging.getLogger(__name__)


PaginatedApiItem = TypeVar("PaginatedApiItem")


class PaginatedAPIResponse(TypedDict, Generic[PaginatedApiItem]):
    next: URL
    previous: URL
    results: list[PaginatedApiItem]


class BaseAPIClient(ABC):
    def __init__(self, session: "ReptorSession"):
        self.session = session


# The actual data transmitted over the REST API usually has a lot more fields than
# what is described here. I am just noting down whatever is actively used in
# repctls code
class NewFindingTemplateTranslation(TypedDict):
    is_main: bool
    language: str
    data: dict[str, str | Any]


class FindingTemplateTranslation(NewFindingTemplateTranslation):
    id: str


class NewFindingTemplate(TypedDict):
    tags: list[str]
    translations: list[NewFindingTemplateTranslation]


class FindingTemplate(TypedDict):
    tags: list[str]
    translations: list[FindingTemplateTranslation]
    details: URL
    id: str


class NewFinding(TypedDict):
    data: dict[str, Any]


class Finding(NewFinding):
    id: str


class TemplatesClient(BaseAPIClient):
    def get(self, *, search: str | None) -> Generator[FindingTemplate]:
        next_page = "/api/v1/findingtemplates/"
        if search:
            next_page += f"?search={search}"
        while next_page:
            res = self.session.get(next_page)
            data = cast(PaginatedAPIResponse[FindingTemplate], res.json())
            next_page = data["next"]
            for item in data["results"]:
                yield item

    def get_details(self, id: str) -> FindingTemplate:
        res = self.session.get(f"/api/v1/findingtemplates/{id}")
        res.raise_for_status()
        return cast(FindingTemplate, res.json())

    def create(self, template: NewFindingTemplate) -> FindingTemplate:
        res = self.session.post("/api/v1/findingtemplates", json=template)
        res.raise_for_status()
        return cast(FindingTemplate, res.json())

    def update(self, template: FindingTemplate) -> None:
        id = template["id"]
        res = self.session.put(f"/api/v1/findingtemplates/{id}", json=template)
        res.raise_for_status()

    def delete(self, template: FindingTemplate) -> None:
        id = template["id"]
        res = self.session.delete(f"/api/v1/findingtemplates/{id}")
        res.raise_for_status()

    def find_one(self, search: str) -> FindingTemplate | None:
        search_results = list(self.get(search=search))
        if len(search_results) > 1:
            raise RepctlException(
                f"Found more than one template matching '{search}', refusing to upsert."
            )
        if len(search_results) == 1:
            return search_results[0]
        return None

    def search_and_upsert(
        self, template: NewFindingTemplate | FindingTemplate, search: str
    ) -> None:
        existing_template = self.find_one(search)
        title = template["translations"][0]["data"]["title"]

        if not existing_template:
            template = cast(NewFindingTemplate, template)
            new_template = self.create(template)
            id = new_template["id"]
            LOGGER.info(f'Created template "{title}" ({id})')
        else:
            template = cast(FindingTemplate, template)
            id = existing_template["id"]
            template["id"] = id
            self.update(template)
            LOGGER.info(f'Updated template "{title}" ({id})')


class FindingsClient(BaseAPIClient):
    def create_from_template(
        self, project_id: str, template_id: str, template_language: str
    ) -> Finding:
        res = self.session.post(
            f"/api/v1/pentestprojects/{project_id}/findings/fromtemplate",
            json=dict(template=template_id, template_language=template_language),
        )
        res.raise_for_status()
        return cast(Finding, res.json())

    def update(self, project_id: str, finding: Finding) -> Finding:
        res = self.session.put(
            f"/api/v1/pentestprojects/{project_id}/findings/{finding['id']}",
            json=finding,
        )
        res.raise_for_status()
        return cast(Finding, res.json())


class ReptorSession(BaseUrlSession):
    def __init__(self, *args, **kwargs):
        api_key = kwargs.pop("api_key")
        super().__init__(*args, **kwargs)
        self.headers.update({"Authorization": f"Bearer {api_key}"})

    @property
    def templates(self) -> TemplatesClient:
        return TemplatesClient(self)

    @property
    def findings(self) -> FindingsClient:
        return FindingsClient(self)


def make_template_id(plain_id: str) -> str:
    return f"{plain_id}-{sha1(plain_id.encode()).hexdigest()}"


_PROJECT_ID_RE = re.compile(r"/projects/([a-z0-9-]+).*")


def parse_project_url(report_url: str) -> tuple[str, str]:
    """Infer reptor base url and project id from reptor_url."""
    try:
        parsed = urlparse(report_url)
    except ValueError as e:
        raise RepctlException(f"Invalid URL: {report_url}") from e
    base_url = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    match = re.match(_PROJECT_ID_RE, parsed.path)
    if not match:
        raise RepctlException("Couldn't find project id in URL")
    project_id = match.group(1)

    return base_url, project_id


# Finding fields configured for Scuba Reports
# Templates only specify a subset of the fields ...
class ScubaFindingTemplateData(TypedDict):
    title: str
    product: str
    groupId: str
    isGroupDescription: bool
    policyId: str
    description: str


# ... and get completed with these by an actual Scuba scan result
class ScubaFindingData(ScubaFindingTemplateData):
    result: str
    criticality: str
    details: str
