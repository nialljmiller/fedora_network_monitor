from pathlib import Path

setup_script = Path("/mnt/data/setup_gmail_relay.sh")
script_content = """#!/bin/bash
set -e

GMAIL_USER="cirrus.noreply@gmail.com"
echo "Enter the Gmail App Password for $GMAIL_USER:"
read -s GMAIL_PASS

# Install necessary packages
sudo dnf install -y postfix cyrus-sasl-plain mailx

# Enable postfix
sudo systemctl enable --now postfix

# Configure main.cf
sudo tee -a /etc/postfix/main.cf > /dev/null <<EOF

# Gmail SMTP Relay
relayhost = [smtp.gmail.com]:587
smtp_use_tls = yes
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-bundle.crt
EOF

# Create sasl_passwd file
sudo bash -c "echo '[smtp.gmail.com]:587 $GMAIL_USER:$GMAIL_PASS' > /etc/postfix/sasl_passwd"
sudo postmap /etc/postfix/sasl_passwd
sudo chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db

# Configure generic maps to rewrite sender
sudo tee /etc/postfix/generic > /dev/null <<EOF
root@localhost    $GMAIL_USER
nill@Cirrus       $GMAIL_USER
EOF
sudo postmap /etc/postfix/generic

# Enable generic mapping
sudo postconf -e "smtp_generic_maps = hash:/etc/postfix/generic"

# Restart postfix
sudo systemctl restart postfix

echo "✅ Gmail relay setup complete! Try sending a test email:"
echo 'echo "Subject: Test from Cirrus\\n\\nHello world" | sendmail -v niall.j.miller@gmail.com'
"""

setup_script.write_text(script_content)
setup_script.chmod(0o755)
setup_script
