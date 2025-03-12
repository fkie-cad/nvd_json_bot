import json

from util.message_card import MessageCard

test_data: str = json.dumps({
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    "themeColor": "4ACF3E",
    "summary": "[Release] New Release Available",
    "sections": [{
        "activityTitle": "There is a new feed release available",
        "activitySubtitle": "test/test",
        "activityImage": "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
        "facts": [{
            "name": "Timestamp",
            "value": "1970-123-123-123"
        }, {
            "name": "Version",
            "value": "v2023-02-01"
        }, {
            "name": "Commit",
            "value": "sha1"
        }],
        "markdown": True
    }],
    "potentialAction": [{
        "@type": "OpenUri",
        "name": "Release",
        "targets": [{
            "os": "default",
            "uri": "https://github.com/python/cpython"
        }]
    }]
})


def test_serialize():
    summary: str = "[Release] New Release Available"
    success: bool = True
    message: str = "There is a new feed release available"
    repo: str = "test/test"
    facts: list[tuple[str, str]] = [
        ("Timestamp", "1970-123-123-123"),
        ("Version", "v2023-02-01"),
        ("Commit", "sha1")
    ]
    action_links: list[tuple[str, str]] = [
        ("Release", "https://github.com/python/cpython")
    ]

    card: MessageCard = MessageCard(summary=summary, success=success, message=message, repo=repo, facts=facts, action_links=action_links)

    assert json.dumps(card.json()) == test_data
