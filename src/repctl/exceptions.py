class RepctlException(Exception):
    def __init__(self, msg, *args) -> None:
        super().__init__(*args)
        self.msg = msg


class SnippetParsingException(RepctlException): ...


class InvalidScubaReport(RepctlException): ...
