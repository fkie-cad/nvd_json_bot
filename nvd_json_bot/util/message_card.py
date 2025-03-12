import dataclasses
from typing import Any


@dataclasses.dataclass
class MessageCard:
    success: bool
    summary: str
    message: str
    repo: str
    facts: list[tuple[str, Any]]
    action_links: list[tuple[str, str]]

    image: str = "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png"

    def json(self) -> dict[str, Any]:
        obj: dict[str, Any] = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "4ACF3E" if self.success else "D63215",
            "summary": self.summary,
            "sections": [
                {
                    "activityTitle": self.message,
                    "activitySubtitle": self.repo,
                    "activityImage": self.image,
                    "facts": [{"name": f[0], "value": f[1]} for f in self.facts],
                    "markdown": True,
                }
            ],
            "potentialAction": [
                {"@type": "OpenUri", "name": a[0], "targets": [{"os": "default", "uri": a[1]}]}
                for a in self.action_links
            ],
        }

        return obj
