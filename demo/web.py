"""
Web-based demo interface for the privacy-preserving digital credential system.
"""

import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, abort

from issuer import Issuer, create_issuer, load_issuer
from holder import Wallet
from verifier import Verifier
from common.utils import (
    get_credentials_dir, get_wallets_dir, get_revocation_dir, load_json
)
from datetime import datetime



app = Flask(__name__)


# Helper functions
def get_all_issuers():
    """Get all issuers."""
    issuer_files = [f for f in os.listdir(get_credentials_dir()) if f.startswith("issuer_")]
    issuers = []
    
    for issuer_file in issuer_files:
        issuer_id = issuer_file.replace("issuer_", "").replace(".json", "")
        issuer = load_issuer(issuer_id)
        issuers.append({
            'id': issuer.issuer_id,
            'name': issuer.name
        })
    
    return issuers


def get_all_wallets():
    """Get all wallets."""
    wallet_files = [f for f in os.listdir(get_wallets_dir()) if f.startswith("wallet_")]
    wallets = []
    
    for wallet_file in wallet_files:
        holder_id = wallet_file.replace("wallet_", "").replace(".json", "")
        wallet = Wallet(holder_id=holder_id)
        wallets.append({
            'id': wallet.holder_id,
            'name': wallet.name
        })
    
    return wallets


# Routes
@app.route('/')
def index():
    """Home page."""
    return render_template('index.html', 
                           issuers=get_all_issuers(),
                           wallets=get_all_wallets())


# Issuer routes
@app.route('/issuer/create', methods=['GET', 'POST'])
def create_issuer_route():
    """Create a new issuer."""
    if request.method == 'POST':
        name = request.form.get('name')
        issuer = create_issuer(name=name)
        return redirect(url_for('index'))
    
    return render_template('create_issuer.html')


# @app.route('/issuer/<issuer_id>')
# def issuer_details(issuer_id):
#     """View issuer details."""
#     issuer = load_issuer(issuer_id)
#     if not issuer:
#         abort(404)
    
#     return render_template('issuer_details.html', issuer=issuer)
# Update issuer_details route to include link to revocation status
# Replace the create_wallet_route function in web.py with this improved version

# Replace the issuer_details route in web.py with this updated version

@app.route('/issuer/<issuer_id>')
def issuer_details(issuer_id):
    """View issuer details."""
    issuer = load_issuer(issuer_id)
    if not issuer:
        abort(404)
    
    # Find credentials issued by this issuer
    credential_files = [f for f in os.listdir(get_credentials_dir()) if f.startswith("credential_")]
    credential_count = 0
    revoked_count = 0
    credentials = []
    
    for credential_file in credential_files:
        credential_data = load_json(os.path.join(get_credentials_dir(), credential_file))
        if credential_data and credential_data.get('issuer_id') == issuer_id:
            credential_count += 1
            credentials.append(credential_data)
            if issuer.revocation_manager.is_revoked(credential_data.get('index', -1)):
                revoked_count += 1
    
    return render_template('issuer_details.html', 
                          issuer=issuer, 
                          credential_count=credential_count,
                          revoked_count=revoked_count,
                          credentials=credentials)

@app.template_filter('timestamp_to_date')
def timestamp_to_date(timestamp):
    """Convert Unix timestamp to human-readable date."""
    if not timestamp:
        return None
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

@app.route('/issuer/<issuer_id>/issue', methods=['GET', 'POST'])
def issue_credential_route(issuer_id):
    """Issue a new credential."""
    issuer = load_issuer(issuer_id)
    if not issuer:
        abort(404)
    
    if request.method == 'POST':
        # Get form data
        holder_id = request.form.get('holder_id')
        credential_type = request.form.get('type')
        
        # Process attributes
        attributes = {}
        for key in request.form:
            if key.startswith('attr_key_'):
                index = key.replace('attr_key_', '')
                attr_key = request.form.get(key)
                attr_value = request.form.get(f'attr_value_{index}')
                if attr_key and attr_value:
                    attributes[attr_key] = attr_value
        
        # Process expiration
        expiration = request.form.get('expiration')
        expiration_date = None
        if expiration:
            try:
                days = int(expiration)
                import time
                expiration_date = int(time.time()) + (days * 86400)
            except ValueError:
                return render_template('issue_credential.html', 
                                       issuer=issuer, 
                                       wallets=get_all_wallets(),
                                       error="Invalid expiration value")
        
        # Issue the credential
        try:
            credential = issuer.issue_credential(
                holder_id=holder_id,
                credential_type=credential_type,
                attributes=attributes,
                expiration_date=expiration_date
            )
            
            # Try to add the credential to the holder's wallet automatically
            try:
                wallet = Wallet(holder_id=holder_id)
                wallet.add_credential(credential)
            except Exception as e:
                print(f"Warning: Could not add credential to wallet: {e}")
            
            # Redirect to the credential details page
            return redirect(url_for('credential_details', credential_id=credential.id))
        
        except Exception as e:
            return render_template('issue_credential.html', 
                                   issuer=issuer, 
                                   wallets=get_all_wallets(),
                                   error=f"Error issuing credential: {str(e)}")
    
    # GET request - show the form
    return render_template('issue_credential.html', 
                          issuer=issuer, 
                          wallets=get_all_wallets())


@app.route('/issuer/<issuer_id>/revoke', methods=['GET', 'POST'])
def revoke_credential_route(issuer_id):
    """Revoke a credential."""
    issuer = load_issuer(issuer_id)
    if not issuer:
        abort(404)
    
    if request.method == 'POST':
        credential_id = request.form.get('credential_id')
        success = issuer.revoke_credential(credential_id)
        return redirect(url_for('issuer_details', issuer_id=issuer_id))
    
    # Get all credentials issued by this issuer
    credentials = []
    credential_files = [f for f in os.listdir(get_credentials_dir()) if f.startswith("credential_")]
    
    for credential_file in credential_files:
        credential_data = load_json(os.path.join(get_credentials_dir(), credential_file))
        if credential_data and credential_data.get('issuer_id') == issuer_id:
            credentials.append(credential_data)
    
    return render_template('revoke_credential.html', 
                          issuer=issuer, 
                          credentials=credentials)


# Wallet routes
# @app.route('/wallet/create', methods=['GET', 'POST'])
# def create_wallet_route():
#     """Create a new wallet."""
#     if request.method == 'POST':
#         name = request.form.get('name')
#         wallet = Wallet(name=name)
#         return redirect(url_for('index'))
    
#     return render_template('create_wallet.html')
# Replace the create_wallet_route function in web.py with this improved version

@app.route('/wallet/create', methods=['GET', 'POST'])
def create_wallet_route():
    """Create a new wallet."""
    if request.method == 'POST':
        name = request.form.get('name')
        if not name:
            return render_template('create_wallet.html', error="Name is required")
        
        wallet = Wallet(name=name)
        print(f"Created wallet with ID: {wallet.holder_id} and name: {wallet.name}")
        
        # Save the wallet
        wallet._save_wallet()
        
        # Redirect to the wallet details page
        return redirect(url_for('wallet_details', holder_id=wallet.holder_id))
    
    return render_template('create_wallet.html')


@app.route('/wallet/<holder_id>')
def wallet_details(holder_id):
    """View wallet details."""
    wallet = Wallet(holder_id=holder_id)
    credentials = wallet.list_credentials()
    
    return render_template('wallet_details.html', 
                          wallet=wallet, 
                          credentials=credentials)


@app.route('/wallet/<holder_id>/credential/<credential_id>')
def wallet_credential_details(holder_id, credential_id):
    """View credential details in a wallet."""
    wallet = Wallet(holder_id=holder_id)
    credential = wallet.get_credential(credential_id)
    if not credential:
        abort(404)
    
    return render_template('wallet_credential_details.html', 
                          wallet=wallet, 
                          credential=credential)


@app.route('/wallet/<holder_id>/present/<credential_id>', methods=['GET', 'POST'])
def present_credential_route(holder_id, credential_id):
    """Create a presentation of a credential."""
    wallet = Wallet(holder_id=holder_id)
    credential = wallet.get_credential(credential_id)
    if not credential:
        abort(404)
    
    # Check if credential is revoked
    is_revoked = False
    try:
        issuer = load_issuer(credential.issuer_id)
        if issuer:
            is_revoked = issuer.revocation_manager.is_revoked(credential.index)
    except Exception:
        pass
    
    # Check if credential is expired
    is_expired = False
    if credential.expiration_date and credential.expiration_date < current_timestamp():
        is_expired = True
    
    if request.method == 'POST':
        selected_attrs = request.form.getlist('attr')
        presentation = wallet.create_presentation(credential_id, selected_attrs if selected_attrs else None)
        
        return render_template('presentation.html', 
                              wallet=wallet, 
                              credential=credential,
                              presentation=presentation,
                              is_revoked=is_revoked,
                              is_expired=is_expired)
    
    return render_template('create_presentation.html', 
                          wallet=wallet, 
                          credential=credential,
                          is_revoked=is_revoked,
                          is_expired=is_expired)


# Verifier routes
@app.route('/verifier')
def verifier_home():
    """Verifier home page."""
    return render_template('verifier.html')


@app.route('/verifier/verify', methods=['POST'])
def verify_credential_route():
    """Verify a credential or presentation."""
    verifier = Verifier()
    
    if 'presentation' in request.form:
        try:
            presentation = json.loads(request.form.get('presentation'))
            is_valid, details = verifier.verify_credential(presentation)
        except Exception as e:
            return jsonify({'valid': False, 'error': str(e)})
    elif 'credential_id' in request.form:
        credential_id = request.form.get('credential_id')
        credential_path = os.path.join(get_credentials_dir(), f"credential_{credential_id}.json")
        
        if not os.path.exists(credential_path):
            return jsonify({'valid': False, 'error': 'Credential not found'})
        
        credential_data = load_json(credential_path)
        from common.models import Credential
        credential = Credential(**credential_data)
        
        is_valid, details = verifier.verify_credential(credential)
    else:
        return jsonify({'valid': False, 'error': 'No credential or presentation provided'})
    
    return jsonify({'valid': is_valid, 'details': details})


@app.route('/credential/<credential_id>')
def credential_details(credential_id):
    """View credential details."""
    credential_path = os.path.join(get_credentials_dir(), f"credential_{credential_id}.json")
    if not os.path.exists(credential_path):
        abort(404)
    
    credential_data = load_json(credential_path)
    if not credential_data:
        abort(404)
    
    # Check if we have access to the issuer and wallet for this credential
    issuers_lookup = {}
    wallets_lookup = {}
    is_revoked = False
    
    # Check if we have the issuer
    issuer_id = credential_data.get('issuer_id')
    if issuer_id:
        try:
            issuer = load_issuer(issuer_id)
            if issuer:
                issuers_lookup[issuer_id] = issuer.name
                # Check revocation status
                is_revoked = issuer.revocation_manager.is_revoked(credential_data.get('index', -1))
        except Exception:
            pass
    
    # Check if we have the wallet
    holder_id = credential_data.get('holder_id')
    if holder_id:
        try:
            wallet_file = os.path.join(get_wallets_dir(), f"wallet_{holder_id}.json")
            if os.path.exists(wallet_file):
                wallet_data = load_json(wallet_file)
                if wallet_data:
                    wallets_lookup[holder_id] = wallet_data.get('name', 'Unknown Holder')
        except Exception:
            pass
    
    return render_template('credential_details.html', 
                          credential=credential_data,
                          issuers_lookup=issuers_lookup,
                          wallets_lookup=wallets_lookup,
                          is_revoked=is_revoked)

@app.route('/issuer/<issuer_id>/revocation-status')
def revocation_status_route(issuer_id):
    """View the revocation status list for an issuer."""
    issuer = load_issuer(issuer_id)
    if not issuer:
        abort(404)
    
    # Get the revocation list
    revocation_list = issuer.revocation_manager.revocation_list
    
    # Prepare the revoked statuses for display
    revoked_statuses = []
    any_revoked = False
    
    for i, status in enumerate(revocation_list.revoked):
        revoked_statuses.append((i, status))
        if status:
            any_revoked = True
    
    # Get all credentials issued by this issuer for reference
    credentials = []
    credential_files = [f for f in os.listdir(get_credentials_dir()) if f.startswith("credential_")]
    
    for credential_file in credential_files:
        credential_data = load_json(os.path.join(get_credentials_dir(), credential_file))
        if credential_data and credential_data.get('issuer_id') == issuer_id:
            credentials.append(credential_data)
    
    # Create a mapping of index to credential details for display
    index_to_credential = {}
    for credential in credentials:
        index = credential.get('index', -1)
        if index >= 0:
            index_to_credential[index] = {
                'id': credential.get('id', ''),
                'type': credential.get('type', ''),
                'holder_id': credential.get('holder_id', '')
            }
    
    return render_template('revocation_status.html', 
                          issuer=issuer, 
                          revocation_list=revocation_list,
                          revoked_statuses=revoked_statuses,
                          any_revoked=any_revoked,
                          index_to_credential=index_to_credential)

@app.route('/issuer/<issuer_id>/toggle-revocation/<int:index>', methods=['POST'])
def toggle_revocation_route(issuer_id, index):
    """Toggle the revocation status of a credential by index."""
    issuer = load_issuer(issuer_id)
    if not issuer:
        abort(404)
    
    # Get the current status
    is_revoked = issuer.revocation_manager.is_revoked(index)
    
    if is_revoked:
        # Unrevoke
        issuer.revocation_manager.unrevoke(index)
    else:
        # Revoke
        issuer.revocation_manager.revoke(index)
    
    return redirect(url_for('revocation_status_route', issuer_id=issuer_id))

@app.route('/issuer/<issuer_id>/direct-revoke/<credential_id>', methods=['POST'])
def direct_revoke_credential_route(issuer_id, credential_id):
    """Directly revoke a credential by its ID."""
    issuer = load_issuer(issuer_id)
    if not issuer:
        abort(404)
    
    success = issuer.revoke_credential(credential_id)
    
    if request.args.get('redirect_to') == 'status':
        return redirect(url_for('revocation_status_route', issuer_id=issuer_id))
    else:
        return redirect(url_for('issuer_details', issuer_id=issuer_id))



if __name__ == '__main__':
    app.run(debug=True)