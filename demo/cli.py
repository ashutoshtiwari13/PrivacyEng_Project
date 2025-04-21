"""
Command-line interface for the privacy-preserving digital credential system.
"""

import os
import json
import click
import time
from datetime import datetime

from ..issuer import Issuer, create_issuer, load_issuer
from ..holder import Wallet
from ..verifier import Verifier
from ..common.utils import get_credentials_dir, get_wallets_dir, get_revocation_dir


@click.group()
def cli():
    """Privacy-Preserving Digital Credential System CLI."""
    pass


# Issuer commands
@cli.group()
def issuer():
    """Commands for credential issuers."""
    pass


@issuer.command('create')
@click.option('--name', '-n', help='Name of the issuer')
def create_issuer_cmd(name):
    """Create a new issuer."""
    issuer = create_issuer(name=name)
    click.echo(f"Created issuer: {issuer.name} (ID: {issuer.issuer_id})")
    click.echo(f"Public key: {issuer.public_key[:8]}...")


@issuer.command('list')
def list_issuers():
    """List all issuers."""
    issuer_files = [f for f in os.listdir(get_credentials_dir()) if f.startswith("issuer_")]
    
    if not issuer_files:
        click.echo("No issuers found.")
        return
    
    click.echo("Available issuers:")
    for issuer_file in issuer_files:
        issuer_id = issuer_file.replace("issuer_", "").replace(".json", "")
        issuer = load_issuer(issuer_id)
        click.echo(f"- {issuer.name} (ID: {issuer.issuer_id})")


@issuer.command('issue')
@click.option('--issuer-id', '-i', required=True, help='ID of the issuer')
@click.option('--holder-id', '-h', required=True, help='ID of the holder')
@click.option('--type', '-t', required=True, help='Type of credential')
@click.option('--attribute', '-a', multiple=True, help='Attribute in the format name=value')
@click.option('--expires', '-e', help='Expiration date in days from now (optional)')
def issue_credential_cmd(issuer_id, holder_id, type, attribute, expires):
    """Issue a credential to a holder."""
    # Load the issuer
    issuer = load_issuer(issuer_id)
    if not issuer:
        click.echo(f"Issuer with ID {issuer_id} not found.")
        return
    
    # Parse attributes
    attributes = {}
    for attr in attribute:
        if '=' in attr:
            key, value = attr.split('=', 1)
            attributes[key] = value
    
    # Parse expiration date
    expiration_date = None
    if expires:
        try:
            days = int(expires)
            expiration_date = int(time.time()) + (days * 86400)  # Convert days to seconds
        except ValueError:
            click.echo("Invalid expiration days.")
            return
    
    # Issue the credential
    credential = issuer.issue_credential(
        holder_id=holder_id, 
        credential_type=type, 
        attributes=attributes, 
        expiration_date=expiration_date
    )
    
    click.echo(f"Issued credential: {credential.id}")
    click.echo(f"Type: {credential.type}")
    click.echo("Attributes:")
    for key, value in credential.attributes.items():
        click.echo(f"  {key}: {value}")
    
    if expiration_date:
        expiration_str = datetime.fromtimestamp(expiration_date).strftime('%Y-%m-%d %H:%M:%S')
        click.echo(f"Expires: {expiration_str}")
    
    click.echo(f"Credential index (for revocation): {credential.index}")


@issuer.command('revoke')
@click.option('--issuer-id', '-i', required=True, help='ID of the issuer')
@click.option('--credential-id', '-c', required=True, help='ID of the credential to revoke')
def revoke_credential_cmd(issuer_id, credential_id):
    """Revoke a credential."""
    # Load the issuer
    issuer = load_issuer(issuer_id)
    if not issuer:
        click.echo(f"Issuer with ID {issuer_id} not found.")
        return
    
    # Load the credential
    credential_path = os.path.join(get_credentials_dir(), f"credential_{credential_id}.json")
    if not os.path.exists(credential_path):
        click.echo(f"Credential with ID {credential_id} not found.")
        return
    
    # Revoke the credential
    success = issuer.revoke_credential(credential_id)
    if success:
        click.echo(f"Credential {credential_id} has been revoked.")
    else:
        click.echo(f"Failed to revoke credential {credential_id}.")


# Wallet commands
@cli.group()
def wallet():
    """Commands for credential wallets."""
    pass


@wallet.command('create')
@click.option('--name', '-n', help='Name of the wallet holder')
def create_wallet_cmd(name):
    """Create a new wallet."""
    wallet = Wallet(name=name)
    click.echo(f"Created wallet for: {wallet.name} (ID: {wallet.holder_id})")


@wallet.command('list')
def list_wallets():
    """List all wallets."""
    wallet_files = [f for f in os.listdir(get_wallets_dir()) if f.startswith("wallet_")]
    
    if not wallet_files:
        click.echo("No wallets found.")
        return
    
    click.echo("Available wallets:")
    for wallet_file in wallet_files:
        holder_id = wallet_file.replace("wallet_", "").replace(".json", "")
        wallet = Wallet(holder_id=holder_id)
        click.echo(f"- {wallet.name} (ID: {wallet.holder_id})")


@wallet.command('credentials')
@click.option('--holder-id', '-h', required=True, help='ID of the holder')
def list_credentials_cmd(holder_id):
    """List all credentials in a wallet."""
    # Load the wallet
    wallet = Wallet(holder_id=holder_id)
    
    credentials = wallet.list_credentials()
    if not credentials:
        click.echo("No credentials found in this wallet.")
        return
    
    click.echo(f"Credentials in wallet of {wallet.name}:")
    for i, credential in enumerate(credentials, 1):
        click.echo(f"{i}. {credential.type} (ID: {credential.id})")
        click.echo(f"   Issuer: {credential.issuer_name}")
        click.echo(f"   Issued: {datetime.fromtimestamp(credential.issuance_date).strftime('%Y-%m-%d')}")
        if credential.expiration_date:
            click.echo(f"   Expires: {datetime.fromtimestamp(credential.expiration_date).strftime('%Y-%m-%d')}")
        click.echo(f"   Attributes: {len(credential.attributes)}")


@wallet.command('show')
@click.option('--holder-id', '-h', required=True, help='ID of the holder')
@click.option('--credential-id', '-c', required=True, help='ID of the credential to show')
def show_credential_cmd(holder_id, credential_id):
    """Show details of a specific credential."""
    # Load the wallet
    wallet = Wallet(holder_id=holder_id)
    
    credential = wallet.get_credential(credential_id)
    if not credential:
        click.echo(f"Credential with ID {credential_id} not found in this wallet.")
        return
    
    click.echo(f"Credential: {credential.id}")
    click.echo(f"Type: {credential.type}")
    click.echo(f"Issuer: {credential.issuer_name} (ID: {credential.issuer_id})")
    click.echo(f"Issued: {datetime.fromtimestamp(credential.issuance_date).strftime('%Y-%m-%d %H:%M:%S')}")
    if credential.expiration_date:
        click.echo(f"Expires: {datetime.fromtimestamp(credential.expiration_date).strftime('%Y-%m-%d %H:%M:%S')}")
    click.echo(f"Revocation index: {credential.index}")
    click.echo("Attributes:")
    for key, value in credential.attributes.items():
        click.echo(f"  {key}: {value}")


@wallet.command('present')
@click.option('--holder-id', '-h', required=True, help='ID of the holder')
@click.option('--credential-id', '-c', required=True, help='ID of the credential to present')
@click.option('--attribute', '-a', multiple=True, help='Attribute to include in the presentation')
def present_credential_cmd(holder_id, credential_id, attribute):
    """Create a presentation of a credential."""
    # Load the wallet
    wallet = Wallet(holder_id=holder_id)
    
    credential = wallet.get_credential(credential_id)
    if not credential:
        click.echo(f"Credential with ID {credential_id} not found in this wallet.")
        return
    
    # Create the presentation
    selective_disclosure = list(attribute) if attribute else None
    presentation = wallet.create_presentation(credential_id, selective_disclosure)
    
    click.echo("Credential Presentation:")
    click.echo(json.dumps(presentation, indent=2))


# Verifier commands
@cli.group()
def verifier():
    """Commands for credential verification."""
    pass


@verifier.command('verify')
@click.option('--presentation', '-p', help='Path to a presentation JSON file')
@click.option('--credential-id', '-c', help='ID of a credential to verify directly')
def verify_credential_cmd(presentation, credential_id):
    """Verify a credential or presentation."""
    verifier = Verifier()
    
    if presentation:
        try:
            with open(presentation, 'r') as f:
                presentation_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            click.echo("Invalid presentation file.")
            return
        
        is_valid, details = verifier.verify_credential(presentation_data)
    elif credential_id:
        credential_path = os.path.join(get_credentials_dir(), f"credential_{credential_id}.json")
        if not os.path.exists(credential_path):
            click.echo(f"Credential with ID {credential_id} not found.")
            return
        
        with open(credential_path, 'r') as f:
            credential_data = json.load(f)
        
        from ..common.models import Credential
        credential = Credential(**credential_data)
        is_valid, details = verifier.verify_credential(credential)
    else:
        click.echo("Either --presentation or --credential-id must be specified.")
        return
    
    if is_valid:
        click.echo("✅ Credential is valid.")
    else:
        click.echo(f"❌ Credential is invalid: {details.get('error', 'Unknown error')}")


if __name__ == '__main__':
    cli()