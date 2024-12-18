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
    content = f"{report.team.name}-{report.report.title}-{report.reporter.username}"
    return hashlib.md5(content.encode()).hexdigest()

def save_report_as_markdown(report):
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
        'query': '''
        query HacktivityPageQuery($querystring: String, $orderBy: HacktivityItemOrderInput, $secureOrderBy: FiltersHacktivityItemFilterOrder, $where: FiltersHacktivityItemFilterInput, $count: Int, $cursor: String, $maxShownVoters: Int) {
            hacktivity_items(first: $count, after: $cursor, query: $querystring, order_by: $orderBy, secure_order_by: $secureOrderBy, where: $where) {
                edges {
                    node {
                        ... on Disclosed {
                            id
                            reporter {
                                username
                            }
                            team {
                                name
                                handle
                                url
                            }
                            report {
                                title
                                url
                            }
                            latest_disclosable_activity_at
                            total_awarded_amount
                            severity_rating
                        }
                    }
                }
            }
        }
        '''
    }

    s = requests.session()
    resp = s.get(url_hacktivity)
    token = re.findall(r'<meta name="csrf-token" content="([^"]*)" />', resp.text)[0]
    response = s.post(url, json=json_data, headers={'x-csrf-token': token})
    return json.loads(response.text)

def load_subscribed_users():
    return [5334463760]

def main():
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token:
        raise ValueError("TELEGRAM_BOT_TOKEN environment variable is required")

    bot = Bot(token=bot_token)
    response_data = fetch_hacktivity()

    if 'data' in response_data and 'hacktivity_items' in response_data['data']:
        for edge in response_data['data']['hacktivity_items']['edges']:
            if edge['node']:
                report = edge['node']
                
                if save_report_as_markdown(Namespace(**report)):
                    try:
                        message = format_telegram_message(Namespace(**report))
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
    else:
        print("No hacktivity items found in response")

if __name__ == "__main__":
    main()
