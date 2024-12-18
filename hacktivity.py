#!/usr/bin/python3

import sys
import requests
import urllib3
import json
import re
import os
from datetime import datetime
from types import SimpleNamespace as Namespace
from telegram import Bot
from telegram.error import TelegramError
import hashlib

REPORTS_DIR = 'reports'
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_report_id(report):
    """Generate a unique ID for a report based on its content"""
    content = f"{report.team.name}-{report.report.title}-{report.reporter.username}"
    return hashlib.md5(content.encode()).hexdigest()

def save_report_as_markdown(report):
    """Save report as markdown file and return True if it's a new report"""
    report_id = generate_report_id(report)
    filepath = os.path.join(REPORTS_DIR, f"{report_id}.md")
    
    if os.path.exists(filepath):
        return False
        
    bounty = str(int(report.total_awarded_amount)) if report.total_awarded_amount else 'N/A'
    severity = getattr(report, 'severity_rating', 'N/A')
    timestamp = datetime.fromisoformat(report.latest_disclosable_activity_at.replace('Z', '+00:00'))
    
    content = f"""# {report.report.title}

- **Program:** {report.team.name}
- **Reporter:** {report.reporter.username}
- **Bounty:** ${bounty}
- **Severity:** {severity}
- **Report URL:** {report.report.url}
- **Published:** {timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

## Report Details
This report was disclosed by {report.reporter.username} to {report.team.name}'s bug bounty program.

[View full report on HackerOne]({report.report.url})
"""
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return True

def format_telegram_message(report):
    """Format a nice-looking message for Telegram"""
    bounty = str(int(report.total_awarded_amount)) if report.total_awarded_amount else 'N/A'
    severity = getattr(report, 'severity_rating', 'N/A')
    
    message = (
        f"🔔 *New Hacktivity Report*\n\n"
        f"*Program:* {report.team.name}\n"
        f"*Title:* {report.report.title}\n"
        f"*Reporter:* {report.reporter.username}\n"
        f"*Bounty:* ${bounty}\n"
        f"*Severity:* {severity}\n\n"
        f"🔗 [View Report]({report.report.url})"
    )
    return message

def fetch_hacktivity():
    url = "https://hackerone.com/graphql"
    url_hacktivity = "https://hackerone.com/hacktivity"
    
    json_data = {
        'operationName': 'HacktivityPageQuery',
        'variables': {
            'querystring': '',
            'where': {
                'report': {
                    'disclosed_at': {
                        '_is_null': False,
                    },
                },
            },
            'secureOrderBy': {
                'latest_disclosable_activity_at': {
                    '_direction': 'DESC',
                },
            },
            'count': 25,
            'maxShownVoters': 10,
        },
        'query': 'query HacktivityPageQuery($querystring: String, $orderBy: HacktivityItemOrderInput, $secureOrderBy: FiltersHacktivityItemFilterOrder, $where: FiltersHacktivityItemFilterInput, $count: Int, $cursor: String, $maxShownVoters: Int) {\n  me {\n    id\n    __typename\n  }\n  hacktivity_items(\n    first: $count\n    after: $cursor\n    query: $querystring\n    order_by: $orderBy\n    secure_order_by: $secureOrderBy\n    where: $where\n  ) {\n    ...HacktivityList\n    __typename\n  }\n}\n\nfragment HacktivityList on HacktivityItemConnection {\n  pageInfo {\n    endCursor\n    hasNextPage\n    __typename\n  }\n  edges {\n    node {\n      ... on HacktivityItemInterface {\n        id\n        databaseId: _id\n        __typename\n      }\n      __typename\n    }\n    ...HacktivityItem\n    __typename\n  }\n  __typename\n}\n\nfragment HacktivityItem on HacktivityItemUnionEdge {\n  node {\n    ... on HacktivityItemInterface {\n      id\n      type: __typename\n    }\n    ... on Undisclosed {\n      id\n      ...HacktivityItemUndisclosed\n      __typename\n    }\n    ... on Disclosed {\n      id\n      ...HacktivityItemDisclosed\n      __typename\n    }\n    ... on HackerPublished {\n      id\n      ...HacktivityItemHackerPublished\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment HacktivityItemUndisclosed on Undisclosed {\n  id\n  votes {\n    total_count\n    __typename\n  }\n  voters: votes(last: $maxShownVoters) {\n    edges {\n      node {\n        id\n        user {\n          id\n          username\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  upvoted: upvoted_by_current_user\n  reporter {\n    id\n    username\n    ...UserLinkWithMiniProfile\n    __typename\n  }\n  team {\n    handle\n    name\n    medium_profile_picture: profile_picture(size: medium)\n    url\n    id\n    ...TeamLinkWithMiniProfile\n    __typename\n  }\n  latest_disclosable_action\n  latest_disclosable_activity_at\n  requires_view_privilege\n  total_awarded_amount\n  currency\n  __typename\n}\n\nfragment TeamLinkWithMiniProfile on Team {\n  id\n  handle\n  name\n  __typename\n}\n\nfragment UserLinkWithMiniProfile on User {\n  id\n  username\n  __typename\n}\n\nfragment HacktivityItemDisclosed on Disclosed {\n  id\n  reporter {\n    id\n    username\n    ...UserLinkWithMiniProfile\n    __typename\n  }\n  votes {\n    total_count\n    __typename\n  }\n  voters: votes(last: $maxShownVoters) {\n    edges {\n      node {\n        id\n        user {\n          id\n          username\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  upvoted: upvoted_by_current_user\n  team {\n    handle\n    name\n    medium_profile_picture: profile_picture(size: medium)\n    url\n    id\n    ...TeamLinkWithMiniProfile\n    __typename\n  }\n  report {\n    id\n    databaseId: _id\n    title\n    substate\n    url\n    __typename\n  }\n  latest_disclosable_action\n  latest_disclosable_activity_at\n  total_awarded_amount\n  severity_rating\n  currency\n  __typename\n}\n\nfragment HacktivityItemHackerPublished on HackerPublished {\n  id\n  reporter {\n    id\n    username\n    ...UserLinkWithMiniProfile\n    __typename\n  }\n  votes {\n    total_count\n    __typename\n  }\n  voters: votes(last: $maxShownVoters) {\n    edges {\n      node {\n        id\n        user {\n          id\n          username\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  upvoted: upvoted_by_current_user\n  team {\n    id\n    handle\n    name\n    medium_profile_picture: profile_picture(size: medium)\n    url\n    ...TeamLinkWithMiniProfile\n    __typename\n  }\n  report {\n    id\n    url\n    title\n    substate\n    __typename\n  }\n  latest_disclosable_activity_at\n  severity_rating\n  __typename\n}\n',
    }

    s = requests.session()
    resp = s.get(url_hacktivity)
    token = re.findall(r'<meta name="csrf-token" content="([^"]*)" />', resp.text)[0]
    response = s.post(url, json=json_data, headers={'x-csrf-token': token})
    return json.loads(response.text, object_hook=lambda d: Namespace(**d))

def load_subscribed_users():
    """Load list of subscribed user chat_ids"""
    return [5334463760]

def main():
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token:
        raise ValueError("TELEGRAM_BOT_TOKEN environment variable is required")

    bot = Bot(token=bot_token)
    data = fetch_hacktivity()

    for edge in data.data.hacktivity_items.edges:
        report = edge.node
        
        if save_report_as_markdown(report):
            try:
                message = format_telegram_message(report)
                chat_ids = load_subscribed_users()
                
                for chat_id in chat_ids:
                    bot.send_message(
                        chat_id=chat_id,
                        text=message,
                        parse_mode='Markdown',
                        disable_web_page_preview=True
                    )
                    
            except TelegramError as e:
                print(f"Failed to send message: {e}")

if __name__ == "__main__":
    main()
