import smtplib
import requests
import json
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# Set up logging
logger = logging.getLogger('certifly')

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

        # Use from_email if available, otherwise construct one from smtp_username
        from_email = settings.get('from_email')
        if not from_email:
            # If smtp_username looks like an email, use it directly
            if '@' in settings['smtp_username']:
                from_email = settings['smtp_username']
            else:
                # Otherwise, try to construct an email using the SMTP server domain
                smtp_domain = settings['smtp_server'].split('.')[-2:] if len(settings['smtp_server'].split('.')) >= 2 else ['example', 'com']
                from_email = f"{settings['smtp_username']}@{'.'.join(smtp_domain)}"
                logger.debug(f"Constructed from_email: {from_email}")

        # Check if we're using SendGrid (common SMTP servers for SendGrid)
        is_sendgrid = any(sg_domain in settings['smtp_server'].lower()
                          for sg_domain in ['sendgrid', 'smtp.sendgrid.net'])

        if is_sendgrid:
            logger.info(f"SendGrid detected. Using verified sender: {from_email}")
            # For SendGrid, the From address must be a verified sender
            # Make sure the from_email is set to a verified sender in your SendGrid account

        msg['From'] = from_email
        msg['To'] = settings['notification_email']
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))

        # Safely convert SMTP port to integer
        try:
            smtp_port = int(settings['smtp_port'])
        except (ValueError, TypeError):
            logger.warning(f"Invalid smtp_port value: {settings['smtp_port']}. Using default value of 587.")
            smtp_port = 587

        logger.debug(f"Connecting to SMTP server: {settings['smtp_server']}:{smtp_port}")
        server = smtplib.SMTP(settings['smtp_server'], smtp_port)
        server.starttls()
        logger.debug(f"Logging in with username: {settings['smtp_username']}")
        server.login(settings['smtp_username'], settings['smtp_password'])
        logger.debug(f"Sending email from {from_email} to {settings['notification_email']}")
        server.send_message(msg)
        server.quit()

        return True, "Email sent successfully"
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Email notification error: {error_msg}")

        # Provide more helpful error message for SendGrid sender identity issues
        if "550" in error_msg and "sender identity" in error_msg.lower():
            return False, (f"Failed to send email: The From address '{from_email}' is not verified with SendGrid. "
                          f"Please verify this sender in your SendGrid account or use a different verified email address.")

        return False, f"Failed to send email: {error_msg}"

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

def send_telegram_notification(settings, title, message):
    """Send a notification to Telegram using bot API"""
    if not settings.get('enabled'):
        return False, "Telegram notifications are disabled"

    if not settings.get('bot_token'):
        return False, "Telegram bot token is not configured"

    if not settings.get('chat_id'):
        return False, "Telegram chat ID is not configured"

    try:
        # Format the message with title and content
        formatted_message = f"*{title}*\n\n{message}\n\nSent at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        # Telegram Bot API endpoint
        api_url = f"https://api.telegram.org/bot{settings['bot_token']}/sendMessage"

        # Prepare payload
        payload = {
            "chat_id": settings['chat_id'],
            "text": formatted_message,
            "parse_mode": "Markdown"
        }

        # Send the request
        response = requests.post(api_url, json=payload)

        # Check response
        if response.status_code == 200:
            response_json = response.json()
            if response_json.get('ok'):
                return True, "Telegram notification sent successfully"
            else:
                return False, f"Failed to send Telegram notification: {response_json.get('description', 'Unknown error')}"
        else:
            return False, f"Failed to send Telegram notification: HTTP {response.status_code}"

    except Exception as e:
        logger.error(f"Error sending Telegram notification: {str(e)}")
        return False, f"Failed to send Telegram notification: {str(e)}"

def send_webhook_notification(settings, title, message):
    """Send a notification to a custom webhook endpoint"""
    if not settings.get('enabled'):
        return False, "Custom webhook notifications are disabled"

    if not settings.get('webhook_url'):
        return False, "Custom webhook URL is not configured"

    try:
        # Prepare payload based on the format specified
        format_type = settings.get('format', 'json')
        headers = {'Content-Type': 'application/json'}

        # Add custom headers if specified
        if settings.get('custom_headers'):
            try:
                custom_headers = json.loads(settings.get('custom_headers', '{}'))
                headers.update(custom_headers)
            except json.JSONDecodeError:
                logger.warning("Invalid custom headers JSON format, using default headers")

        # Default JSON payload
        payload = {
            "title": title,
            "message": message,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # Add custom fields if specified
        if settings.get('custom_fields'):
            try:
                custom_fields = json.loads(settings.get('custom_fields', '{}'))
                payload.update(custom_fields)
            except json.JSONDecodeError:
                logger.warning("Invalid custom fields JSON format, using default payload")

        # Send the request
        response = requests.post(
            settings['webhook_url'],
            data=json.dumps(payload),
            headers=headers
        )

        # Check response
        if 200 <= response.status_code < 300:
            return True, "Custom webhook notification sent successfully"
        else:
            return False, f"Failed to send custom webhook notification: HTTP {response.status_code}"

    except Exception as e:
        logger.error(f"Error sending custom webhook notification: {str(e)}")
        return False, f"Failed to send custom webhook notification: {str(e)}"

def send_sms_notification(settings, title, message):
    """Send an SMS notification using Twilio"""
    if not settings.get('enabled'):
        return False, "SMS notifications are disabled"

    if not all([
        settings.get('account_sid'),
        settings.get('auth_token'),
        settings.get('from_number'),
        settings.get('to_number')
    ]):
        return False, "SMS configuration is incomplete"

    try:
        # Import Twilio client only when needed to avoid dependency issues
        try:
            from twilio.rest import Client
        except ImportError:
            return False, "Twilio package is not installed. Please install it with 'pip install twilio'"

        # Initialize Twilio client
        client = Client(settings['account_sid'], settings['auth_token'])

        # Format the message (combine title and message, but keep it short for SMS)
        sms_text = f"{title}\n\n{message[:160]}..." if len(message) > 160 else f"{title}\n\n{message}"

        # Send the SMS
        message = client.messages.create(
            body=sms_text,
            from_=settings['from_number'],
            to=settings['to_number']
        )

        return True, f"SMS notification sent successfully (SID: {message.sid})"

    except ImportError as e:
        return False, f"Failed to import Twilio: {str(e)}"
    except Exception as e:
        logger.error(f"Error sending SMS notification: {str(e)}")
        return False, f"Failed to send SMS notification: {str(e)}"

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
    elif notification_type == 'telegram':
        return send_telegram_notification(settings, title, message)
    elif notification_type == 'webhook':
        return send_webhook_notification(settings, title, message)
    elif notification_type == 'sms':
        return send_sms_notification(settings, title, message)
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
    elif notification_type == 'telegram':
        return send_telegram_notification(settings, title, message)
    elif notification_type == 'webhook':
        return send_webhook_notification(settings, title, message)
    elif notification_type == 'sms':
        return send_sms_notification(settings, title, message)
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
    elif notification_type == 'telegram':
        return send_telegram_notification(settings, title, message)
    elif notification_type == 'webhook':
        return send_webhook_notification(settings, title, message)
    elif notification_type == 'sms':
        return send_sms_notification(settings, title, message)
    else:
        return False, f"Unknown notification type: {notification_type}"
