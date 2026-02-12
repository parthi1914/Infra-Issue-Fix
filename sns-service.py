"""
SNS/SES Service for sending alert notifications.
Uses SES for HTML email delivery (SNS does not support HTML rendering).
"""
import boto3
import json
import logging
import os
import warnings
from datetime import datetime
from typing import Dict, List, Optional

# Suppress SSL warnings for corporate proxy environments
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import streamlit as st
    HAS_STREAMLIT = True
except ImportError:
    HAS_STREAMLIT = False

log = logging.getLogger(__name__)

# ===========================================================================
# Configuration
# ===========================================================================
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:395527390279:av-edm-streamlit-alert"

# SES verified sender email - CHANGE THIS to your verified SES sender address
SES_SENDER_EMAIL = "edm-alerts@geaerospace.com"

AWS_REGION = "us-east-1"

# ===========================================================================
# Hardcoded AWS Credentials (for deployment/development)
# Fresh SAML credentials - expires 2026-02-12T04:43:32+00:00
# ===========================================================================


# Set to True to use hardcoded credentials above
_USE_HARDCODED = True  # Using hardcoded SAML credentials


def _get_boto_config():
    """Get common boto config."""
    from botocore.config import Config
    return Config(
        signature_version='v4',
        retries={'max_attempts': 3, 'mode': 'standard'}
    )


def _get_client_kwargs():
    """Get common client kwargs for hardcoded credentials."""
    kwargs = {
        "region_name": _HARDCODED_AWS.get("region", AWS_REGION),
        "aws_access_key_id": _HARDCODED_AWS["access_key_id"],
        "aws_secret_access_key": _HARDCODED_AWS["secret_access_key"],
        "verify": False,
        "config": _get_boto_config(),
    }
    if _HARDCODED_AWS.get("session_token"):
        kwargs["aws_session_token"] = _HARDCODED_AWS["session_token"]
    return kwargs


def get_ses_client():
    """
    Get boto3 SES client for sending HTML emails.
    """
    try:
        if _USE_HARDCODED and _HARDCODED_AWS.get("access_key_id") and _HARDCODED_AWS["access_key_id"] != "YOUR_ACCESS_KEY_ID":
            log.info("Using hardcoded AWS credentials for SES")
            return boto3.client("ses", **_get_client_kwargs())
        return boto3.client("ses", region_name=AWS_REGION, verify=False, config=_get_boto_config())
    except Exception as e:
        log.error(f"Failed to create SES client: {e}")
        return None


def get_sns_client():
    """
    Get boto3 SNS client with credentials from multiple sources.

    Tries in order:
    1. Hardcoded credentials (if _USE_HARDCODED = True)
    2. Streamlit secrets (aws section)
    3. Environment variables
    4. AWS SSO/default profile
    5. Default credentials chain (IAM role, ~/.aws/credentials)
    """
    from botocore.config import Config

    boto_config = Config(
        signature_version='v4',
        retries={'max_attempts': 3, 'mode': 'standard'}
    )

    try:
        # Method 0: Use hardcoded credentials (highest priority when enabled)
        if _USE_HARDCODED and _HARDCODED_AWS.get("access_key_id") and _HARDCODED_AWS["access_key_id"] != "YOUR_ACCESS_KEY_ID":
            client_kwargs = {
                "region_name": _HARDCODED_AWS.get("region", AWS_REGION),
                "aws_access_key_id": _HARDCODED_AWS["access_key_id"],
                "aws_secret_access_key": _HARDCODED_AWS["secret_access_key"],
                "verify": False,
                "config": boto_config,
            }
            if _HARDCODED_AWS.get("session_token"):
                client_kwargs["aws_session_token"] = _HARDCODED_AWS["session_token"]

            log.info("Using hardcoded AWS credentials for SNS")
            return boto3.client("sns", **client_kwargs)

        # Method 1: Try streamlit secrets
        if HAS_STREAMLIT:
            try:
                aws_cfg = dict(st.secrets.get("aws", {}))
                if aws_cfg.get("access_key_id") and aws_cfg.get("secret_access_key"):
                    client_kwargs = {
                        "region_name": aws_cfg.get("region", AWS_REGION),
                        "aws_access_key_id": aws_cfg["access_key_id"],
                        "aws_secret_access_key": aws_cfg["secret_access_key"],
                        "verify": False,
                        "config": boto_config,
                    }
                    if aws_cfg.get("session_token"):
                        client_kwargs["aws_session_token"] = aws_cfg["session_token"]

                    return boto3.client("sns", **client_kwargs)
            except Exception:
                pass

        # Method 2: Try SAML profile
        try:
            session = boto3.Session(profile_name='saml', region_name=AWS_REGION)
            client = session.client("sns", verify=False, config=boto_config)
            log.info("Using SAML profile for SNS")
            return client
        except Exception as e:
            log.debug(f"SAML profile failed: {e}")

        # Method 3: Try environment variables
        access_key = os.environ.get("AWS_ACCESS_KEY_ID")
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
        if access_key and secret_key:
            return boto3.client(
                "sns",
                region_name=os.environ.get("AWS_REGION", AWS_REGION),
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                verify=False,
                config=boto_config,
            )

        # Method 4: Try default AWS profile
        try:
            session = boto3.Session(region_name=AWS_REGION)
            client = session.client("sns", verify=False, config=boto_config)
            client.get_topic_attributes(TopicArn=SNS_TOPIC_ARN)
            return client
        except Exception as e:
            log.debug(f"Default session failed: {e}")

        # Method 5: Try specific profile names
        for profile in [None, "default", "sso"]:
            try:
                session = boto3.Session(profile_name=profile, region_name=AWS_REGION)
                client = session.client("sns", verify=False, config=boto_config)
                return client
            except Exception:
                continue

        # Final fallback
        return boto3.client("sns", region_name=AWS_REGION, verify=False, config=boto_config)

    except Exception as e:
        log.error(f"Failed to create SNS client: {e}")
        return None


def _get_sns_email_subscribers(sns_client) -> List[str]:
    """
    Retrieve email subscriber addresses from the SNS topic.
    """
    emails = []
    try:
        paginator = sns_client.get_paginator('list_subscriptions_by_topic')
        for page in paginator.paginate(TopicArn=SNS_TOPIC_ARN):
            for sub in page.get('Subscriptions', []):
                if sub.get('Protocol') == 'email' and sub.get('Endpoint'):
                    emails.append(sub['Endpoint'])
    except Exception as e:
        log.error(f"Failed to list SNS email subscribers: {e}")
    return emails


def send_error_alert(
    engine_serial: str,
    tail_number: str,
    operator_code: str,
    failed_systems: List[Dict],
) -> Dict:
    """
    Send error alert notification via SES (HTML email).

    Reads subscriber emails from the SNS topic and sends a properly
    rendered HTML email using SES instead of SNS (which only supports
    plain text email).

    Args:
        engine_serial: ESN identifier
        tail_number: Tail number (diagnostic_tail)
        operator_code: Operator code
        failed_systems: List of failed system details

    Returns:
        Dict with status and message
    """
    try:
        sns_client = get_sns_client()
        if not sns_client:
            return {"success": False, "message": "Failed to connect to AWS SNS"}

        ses_client = get_ses_client()
        if not ses_client:
            return {"success": False, "message": "Failed to connect to AWS SES"}

        # Build alert message
        now = datetime.utcnow()

        # Count of failed systems for severity
        failure_count = len(failed_systems)
        severity = "CRITICAL" if failure_count >= 3 else "HIGH" if failure_count >= 2 else "MEDIUM"

        # Build HTML table rows for failed systems
        failed_rows = "".join([
            f"<tr><td>{idx+1}</td><td>{sys_info.get('system','Unknown')}</td>"
            f"<td>CRITICAL - FAILURE DETECTED</td>"
            f"<td>{sys_info.get('reason','Data flow interruption detected')}</td>"
            f"<td>{sys_info.get('last_update','N/A')}</td></tr>"
            for idx, sys_info in enumerate(failed_systems)
        ])

        # Build the message body with enterprise HTML formatting
        message_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset='UTF-8'>
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #222; background: #f7f7fa; }}
    .header {{ background: #003366; color: #fff; padding: 24px 0; text-align: center; font-size: 22px; font-weight: 700; letter-spacing: 1px; }}
    .subheader {{ background: #e5eaf5; color: #003366; padding: 8px 0; text-align: center; font-size: 16px; font-weight: 600; border-bottom: 2px solid #003366; }}
    .section {{ margin: 24px 0 0 0; }}
    .section-title {{ background: #f0f4f8; color: #003366; font-size: 15px; font-weight: 700; padding: 8px 16px; border-left: 4px solid #003366; margin-bottom: 8px; }}
    .info-table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; }}
    .info-table td {{ padding: 8px 12px; border-bottom: 1px solid #e5eaf5; font-size: 14px; }}
    .info-table th {{ background: #e5eaf5; color: #003366; font-weight: 600; padding: 8px 12px; font-size: 14px; }}
    .fail-table th {{ background: #ffe5e5; color: #b30000; }}
    .fail-table td {{ background: #fff6f6; color: #b30000; }}
    .footer {{ background: #e5eaf5; color: #003366; text-align: center; padding: 16px 0; font-size: 13px; margin-top: 32px; border-top: 2px solid #003366; }}
  </style>
</head>
<body>
  <div class='header'>GE Aerospace - EDM Data Observability Platform</div>
  <div class='subheader'>Automated Alert Notification</div>

  <div class='section'>
    <div class='section-title'>Alert Summary</div>
    <table class='info-table'>
      <tr><th>Alert Type</th><td>Data Pipeline Failure</td></tr>
      <tr><th>Severity Level</th><td>{severity}</td></tr>
      <tr><th>Alert Time</th><td>{now.strftime('%B %d, %Y at %H:%M:%S')} UTC</td></tr>
      <tr><th>Reference ID</th><td>EDM-{now.strftime('%Y%m%d%H%M%S')}</td></tr>
    </table>
  </div>

  <div class='section'>
    <div class='section-title'>Asset Information</div>
    <table class='info-table'>
      <tr><th>Engine Serial Number (ESN)</th><td>{engine_serial}</td></tr>
      <tr><th>Aircraft Tail Number</th><td>{tail_number}</td></tr>
      <tr><th>Operator Code</th><td>{operator_code or 'Not Specified'}</td></tr>
    </table>
  </div>

  <div class='section'>
    <div class='section-title'>System Failure Details ({failure_count} System{'s' if failure_count != 1 else ''})</div>
    <table class='info-table fail-table'>
      <tr><th>#</th><th>System</th><th>Status</th><th>Issue</th><th>Last Successful Update</th></tr>
      {failed_rows}
    </table>
  </div>

  <div class='section'>
    <div class='section-title'>Recommended Actions</div>
    <ul style='font-size:14px;color:#003366;'>
      <li>Review the affected system(s) data pipeline status</li>
      <li>Check upstream data source connectivity</li>
      <li>Verify data transformation processes are running</li>
      <li>Escalate to Data Engineering team if issue persists</li>
    </ul>
  </div>

  <div class='section'>
    <div class='section-title'>Contact & Support</div>
    <table class='info-table'>
      <tr><th>Data Engineering Team</th><td>edm-support@geaerospace.com</td></tr>
      <tr><th>Dashboard URL</th><td>EDM Data Observability Portal</td></tr>
    </table>
  </div>

  <div class='footer'>
    This is an automated notification from the EDM Data Observability Platform.<br>
    Please do not reply directly to this message.<br><br>
    &copy; {now.year} GE Aerospace. All rights reserved.
  </div>
</body>
</html>"""

        # Build subject line
        subject = f"[{severity}] EDM Alert: Data Pipeline Failure Detected - ESN {engine_serial} | Aircraft {tail_number}"

        # Plain text fallback for non-HTML email clients
        plain_text = (
            f"EDM Alert: Data Pipeline Failure Detected\n"
            f"Severity: {severity}\n"
            f"ESN: {engine_serial}\n"
            f"Aircraft: {tail_number}\n"
            f"Operator: {operator_code or 'Not Specified'}\n"
            f"Failed Systems: {failure_count}\n"
            f"Time: {now.strftime('%B %d, %Y at %H:%M:%S')} UTC\n"
        )

        # Get subscriber emails from SNS topic
        subscriber_emails = _get_sns_email_subscribers(sns_client)
        if not subscriber_emails:
            return {"success": False, "message": "No email subscribers found on SNS topic. Add email subscriptions to the topic first."}

        # Send HTML email via SES
        response = ses_client.send_email(
            Source=SES_SENDER_EMAIL,
            Destination={
                "ToAddresses": subscriber_emails
            },
            Message={
                "Subject": {
                    "Data": subject,
                    "Charset": "UTF-8"
                },
                "Body": {
                    "Html": {
                        "Data": message_body,
                        "Charset": "UTF-8"
                    },
                    "Text": {
                        "Data": plain_text,
                        "Charset": "UTF-8"
                    }
                }
            }
        )

        message_id = response.get("MessageId", "")
        log.info(f"HTML alert sent via SES successfully. MessageId: {message_id}")

        return {
            "success": True,
            "message": f"Alert sent successfully! Message ID: {message_id}",
            "message_id": message_id
        }

    except Exception as e:
        log.error(f"Failed to send alert: {e}")
        return {
            "success": False,
            "message": f"Failed to send alert: {str(e)}"
        }


def test_sns_connection() -> bool:
    """Test if SNS connection is working."""
    try:
        client = get_sns_client()
        if client:
            client.get_topic_attributes(TopicArn=SNS_TOPIC_ARN)
            return True
    except Exception as e:
        log.error(f"SNS connection test failed: {e}")
    return False
