import logging
import sys
import os
from core.scanners.dast_scanner import scan_url
from core.utils.vulnerability_formatter import format_vulnerabilities_as_markdown
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Create Flask app
app = Flask(__name__, template_folder='codescanai/web/templates', static_folder='codescanai/web/static')
app.config['SECRET_KEY'] = 'your-secret-key'

# Define form
class DastScanForm(FlaskForm):
    target_url = StringField('Target URL', validators=[DataRequired()])
    submit = SubmitField('Scan')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = DastScanForm()
    
    if form.validate_on_submit():
        # Get the target URL
        target_url = form.target_url.data
        
        # Run DAST scan
        logging.info(f"Running DAST scan on {target_url}")
        vulnerabilities = scan_url(target_url, use_basic_scanner=True)
        
        # Format the results
        formatted_results = format_vulnerabilities_as_markdown(vulnerabilities)
        
        # Store the results in the session
        session['scan_results'] = formatted_results
        
        # Redirect to the results page
        return redirect(url_for('results'))
    
    return render_template('scan.html', form=form)

@app.route('/results')
def results():
    # Get the results from the session
    formatted_results = session.get('scan_results', None)
    
    if not formatted_results:
        # If no results, redirect to the scan page
        flash('No scan results found. Please run a scan first.', 'warning')
        return redirect(url_for('index'))
    
    return render_template('results.html', results=formatted_results, no_results=False)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
