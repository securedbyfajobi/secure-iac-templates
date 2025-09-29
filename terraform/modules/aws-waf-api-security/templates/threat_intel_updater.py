#!/usr/bin/env python3
"""
AWS WAF Threat Intelligence Updater
Enterprise-grade threat intelligence automation for AWS WAF IP sets
"""

import json
import boto3
import requests
import logging
from typing import List, Set, Dict, Any
from datetime import datetime, timedelta
import hashlib
import os
import re

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
wafv2_client = boto3.client('wafv2')
ssm_client = boto3.client('ssm')

# Configuration
IP_SET_ID = os.environ.get('IP_SET_ID', '${ip_set_id}')
REGION = os.environ.get('REGION', 'us-east-1')
MAX_IPS_PER_SET = 10000  # AWS WAF limit

# Threat intelligence sources
THREAT_INTEL_SOURCES = {
    'abuse_ch': {
        'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        'format': 'text',
        'comment_char': '#'
    },
    'spamhaus': {
        'url': 'https://www.spamhaus.org/drop/drop.txt',
        'format': 'text',
        'comment_char': ';'
    },
    'emergingthreats': {
        'url': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
        'format': 'text',
        'comment_char': '#'
    },
    'alienvault': {
        'url': 'https://reputation.alienvault.com/reputation.generic',
        'format': 'text',
        'comment_char': '#'
    }
}

class ThreatIntelligenceUpdater:
    """Enterprise threat intelligence updater for AWS WAF"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AWS-WAF-ThreatIntel-Updater/1.0'
        })

    def fetch_threat_ips(self, source_name: str, source_config: Dict[str, Any]) -> Set[str]:
        """Fetch threat IPs from a source"""
        try:
            logger.info(f"Fetching threat intelligence from {source_name}")

            response = self.session.get(
                source_config['url'],
                timeout=30,
                verify=True
            )
            response.raise_for_status()

            ips = set()
            comment_char = source_config.get('comment_char', '#')

            for line in response.text.strip().split('\n'):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith(comment_char):
                    continue

                # Extract IP/CIDR from line
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if self.validate_ip_cidr(ip):
                        ips.add(ip)

            logger.info(f"Fetched {len(ips)} IPs from {source_name}")
            return ips

        except Exception as e:
            logger.error(f"Error fetching from {source_name}: {str(e)}")
            return set()

    def validate_ip_cidr(self, ip_cidr: str) -> bool:
        """Validate IP or CIDR format"""
        try:
            import ipaddress

            if '/' in ip_cidr:
                ipaddress.IPv4Network(ip_cidr, strict=False)
            else:
                ipaddress.IPv4Address(ip_cidr)
                # Convert single IP to /32 CIDR
                ip_cidr = f"{ip_cidr}/32"

            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    def normalize_ip_cidr(self, ip_cidr: str) -> str:
        """Normalize IP/CIDR notation"""
        try:
            import ipaddress

            if '/' not in ip_cidr:
                ip_cidr = f"{ip_cidr}/32"

            network = ipaddress.IPv4Network(ip_cidr, strict=False)
            return str(network)
        except Exception:
            return ip_cidr

    def get_current_ip_set(self) -> Set[str]:
        """Get current IPs from WAF IP set"""
        try:
            response = wafv2_client.get_ip_set(
                Scope='REGIONAL',
                Id=IP_SET_ID
            )

            current_ips = set(response['IPSet']['Addresses'])
            logger.info(f"Current IP set contains {len(current_ips)} addresses")
            return current_ips

        except Exception as e:
            logger.error(f"Error getting current IP set: {str(e)}")
            return set()

    def update_ip_set(self, new_ips: Set[str]) -> bool:
        """Update WAF IP set with new IPs"""
        try:
            # Get current IP set for lock token
            response = wafv2_client.get_ip_set(
                Scope='REGIONAL',
                Id=IP_SET_ID
            )

            lock_token = response['LockToken']
            current_ips = set(response['IPSet']['Addresses'])

            # Normalize all IPs
            normalized_ips = {self.normalize_ip_cidr(ip) for ip in new_ips}

            # Combine with current IPs (keep existing ones)
            combined_ips = current_ips.union(normalized_ips)

            # Limit to max allowed IPs
            if len(combined_ips) > MAX_IPS_PER_SET:
                logger.warning(f"IP set would exceed limit. Keeping most recent {MAX_IPS_PER_SET} IPs")
                combined_ips = set(list(combined_ips)[:MAX_IPS_PER_SET])

            # Only update if there are changes
            if combined_ips != current_ips:
                logger.info(f"Updating IP set with {len(combined_ips)} total addresses")

                wafv2_client.update_ip_set(
                    Scope='REGIONAL',
                    Id=IP_SET_ID,
                    Addresses=list(combined_ips),
                    LockToken=lock_token
                )

                # Store update metadata
                self.store_update_metadata(len(combined_ips), len(normalized_ips))

                logger.info("IP set updated successfully")
                return True
            else:
                logger.info("No changes needed to IP set")
                return False

        except Exception as e:
            logger.error(f"Error updating IP set: {str(e)}")
            return False

    def store_update_metadata(self, total_ips: int, new_ips: int):
        """Store update metadata in Parameter Store"""
        try:
            metadata = {
                'last_update': datetime.utcnow().isoformat(),
                'total_ips': total_ips,
                'new_ips_added': new_ips,
                'sources_used': list(THREAT_INTEL_SOURCES.keys()),
                'region': REGION
            }

            ssm_client.put_parameter(
                Name=f'/waf/threat-intel/{IP_SET_ID}/metadata',
                Value=json.dumps(metadata),
                Type='String',
                Overwrite=True,
                Description='Threat intelligence update metadata'
            )

        except Exception as e:
            logger.warning(f"Could not store metadata: {str(e)}")

    def get_whitelist_ips(self) -> Set[str]:
        """Get whitelisted IPs that should never be blocked"""
        try:
            response = ssm_client.get_parameter(
                Name=f'/waf/threat-intel/{IP_SET_ID}/whitelist',
                WithDecryption=True
            )

            whitelist = json.loads(response['Parameter']['Value'])
            return set(whitelist.get('ips', []))

        except ssm_client.exceptions.ParameterNotFound:
            logger.info("No whitelist found")
            return set()
        except Exception as e:
            logger.warning(f"Error getting whitelist: {str(e)}")
            return set()

    def run(self) -> Dict[str, Any]:
        """Main execution method"""
        logger.info("Starting threat intelligence update")

        results = {
            'status': 'success',
            'sources_processed': 0,
            'total_ips_fetched': 0,
            'ips_added': 0,
            'errors': []
        }

        try:
            # Get whitelist
            whitelist_ips = self.get_whitelist_ips()
            if whitelist_ips:
                logger.info(f"Using whitelist with {len(whitelist_ips)} IPs")

            # Fetch from all sources
            all_threat_ips = set()

            for source_name, source_config in THREAT_INTEL_SOURCES.items():
                threat_ips = self.fetch_threat_ips(source_name, source_config)

                if threat_ips:
                    # Remove whitelisted IPs
                    threat_ips = threat_ips - whitelist_ips
                    all_threat_ips.update(threat_ips)
                    results['sources_processed'] += 1
                else:
                    results['errors'].append(f"Failed to fetch from {source_name}")

            results['total_ips_fetched'] = len(all_threat_ips)

            if all_threat_ips:
                # Update IP set
                if self.update_ip_set(all_threat_ips):
                    results['ips_added'] = len(all_threat_ips)
                    logger.info("Threat intelligence update completed successfully")
                else:
                    results['status'] = 'partial_success'
                    results['errors'].append("Failed to update IP set")
            else:
                logger.warning("No threat IPs fetched from any source")
                results['status'] = 'no_data'

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            results['status'] = 'error'
            results['errors'].append(str(e))

        return results

def handler(event, context):
    """Lambda handler function"""
    updater = ThreatIntelligenceUpdater()
    results = updater.run()

    return {
        'statusCode': 200 if results['status'] == 'success' else 500,
        'body': json.dumps(results, indent=2)
    }

if __name__ == '__main__':
    # For local testing
    results = handler({}, {})
    print(json.dumps(results, indent=2))