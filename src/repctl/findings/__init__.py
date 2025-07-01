from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace

from repctl.sysreptor import ReptorSession, make_template_id


class FindingLoader(ABC):
    name: str

    def __init__(self, session: ReptorSession, project_id: str):
        self.session = session
        self.project_id = project_id

    @classmethod
    def get_template_id(cls, id: str):
        return make_template_id(f"{cls.name}-{id}")

    @classmethod
    def configure_parser(cls, parser: ArgumentParser): ...

    @abstractmethod
    def __call__(self, args: Namespace): ...
