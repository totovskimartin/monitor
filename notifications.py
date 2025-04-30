import smtplib
import requests
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

def send_email_notification(settings, subject, message):
    """Send an email notification using SMTP"""
    if not settings.get('enabled'):
        return False, "Email notifications are disabled"
    
    if not all([
        settings.get('smtp_server'),
        settings.get('smtp_port'),
        settings.get('smtp_username'),
        settings.get('smtp_password'),
        settings.get('notification_email')
    ]):
        return False, "Email configuration is incomplete"
    
    try:
        msg = MIMEMultipart()
        msg['From'] = settings['smtp_username']
        msg['To'] = settings['notification_email']
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))
        
        server = smtplib.SMTP(settings['smtp_server'], int(settings['smtp_port']))
        server.starttls()
        server.login(settings['smtp_username'], settings['smtp_password'])
        server.send_message(msg)
        server.quit()
        
        return True, "Email sent successfully"
    except Exception as e:
        return False, f"Failed to send email: {str(e)}"

def send_teams_notification(settings, title, message):
    """Send a notification to Microsoft Teams using webhook"""
    if not settings.get('enabled'):
        return False, "Microsoft Teams notifications are disabled"
    
    if not settings.get('webhook_url'):
        return False, "Microsoft Teams webhook URL is not configured"
    
    try:
        # Format for Teams message card
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": title,
            "sections": [{
                "activityTitle": title,
                "activitySubtitle": f"Sent at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "text": message
            }]
        }
        
        response = requests.post(
            settings['webhook_url'],
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            return True, "Microsoft Teams notification sent successfully"
        else:
            return False, f"Failed to send Microsoft Teams notification: HTTP {response.status_code}"
    
    except Exception as e:
        return False, f"Failed to send Microsoft Teams notification: {str(e)}"

def send_slack_notification(settings, title, message):
    """Send a notification to Slack using webhook"""
    if not settings.get('enabled'):
        return False, "Slack notifications are disabled"
    
    if not settings.get('webhook_url'):
        return False, "Slack webhook URL is not configured"
    
    try:
        # Format for Slack message
        payload = {
            "text": title,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": title
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"Sent at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        }
                    ]
                }
            ]
        }
        
        # Add channel if specified
        if settings.get('channel'):
            payload['channel'] = settings['channel']
        
        response = requests.post(
            settings['webhook_url'],
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            return True, "Slack notification sent successfully"
        else:
            return False, f"Failed to send Slack notification: HTTP {response.status_code}"
    
    except Exception as e:
        return False, f"Failed to send Slack notification: {str(e)}"

def send_discord_notification(settings, title, message):
    """Send a notification to Discord using webhook"""
    if not settings.get('enabled'):
        return False, "Discord notifications are disabled"
    
    if not settings.get('webhook_url'):
        return False, "Discord webhook URL is not configured"
    
    try:
        # Format for Discord message
        payload = {
            "content": None,
            "embeds": [
                {
                    "title": title,
                    "description": message,
                    "color": 3447003,  # Blue color
                    "footer": {
                        "text": f"Sent at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    }
                }
            ]
        }
        
        # Add username if specified
        if settings.get('username'):
            payload['username'] = settings['username']
        
        response = requests.post(
            settings['webhook_url'],
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 204:  # Discord returns 204 No Content on success
            return True, "Discord notification sent successfully"
        else:
            return False, f"Failed to send Discord notification: HTTP {response.status_code}"
    
    except Exception as e:
        return False, f"Failed to send Discord notification: {str(e)}"

def send_test_notification(notification_type, settings):
    """Send a test notification to the specified platform"""
    title = "Certifly Test Notification"
    message = "This is a test notification from Certifly. If you're seeing this, your notification settings are working correctly!"
    
    if notification_type == 'email':
        return send_email_notification(settings, title, message)
    elif notification_type == 'teams':
        return send_teams_notification(settings, title, message)
    elif notification_type == 'slack':
        return send_slack_notification(settings, title, message)
    elif notification_type == 'discord':
        return send_discord_notification(settings, title, message)
    else:
        return False, f"Unknown notification type: {notification_type}"

def send_certificate_expiry_notification(notification_type, settings, cert):
    """Send a certificate expiry notification to the specified platform"""
    title = f"SSL Certificate Expiry Alert - {cert.domain}"
    message = f"""
SSL Certificate Expiry Alert

Domain: {cert.domain}
Status: {cert.status.upper()}
Days Remaining: {cert.days_remaining}
Expiry Date: {cert.expiry_date.strftime('%Y-%m-%d')}

Please take necessary action to renew the certificate.
"""
    
    if notification_type == 'email':
        return send_email_notification(settings, title, message)
    elif notification_type == 'teams':
        return send_teams_notification(settings, title, message)
    elif notification_type == 'slack':
        return send_slack_notification(settings, title, message)
    elif notification_type == 'discord':
        return send_discord_notification(settings, title, message)
    else:
        return False, f"Unknown notification type: {notification_type}"

def send_domain_expiry_notification(notification_type, settings, domain):
    """Send a domain expiry notification to the specified platform"""
    title = f"Domain Expiry Alert - {domain.name}"
    message = f"""
Domain Expiry Alert

Domain: {domain.name}
Status: {domain.status.upper()}
Days Remaining: {domain.days_remaining}
Expiry Date: {domain.expiry_date.strftime('%Y-%m-%d')}
Registrar: {domain.registrar}

Please take necessary action to renew the domain.
"""
    
    if notification_type == 'email':
        return send_email_notification(settings, title, message)
    elif notification_type == 'teams':
        return send_teams_notification(settings, title, message)
    elif notification_type == 'slack':
        return send_slack_notification(settings, title, message)
    elif notification_type == 'discord':
        return send_discord_notification(settings, title, message)
    else:
        return False, f"Unknown notification type: {notification_type}"
