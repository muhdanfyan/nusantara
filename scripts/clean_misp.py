import re

with open('setup.sh', 'r', encoding='utf-8') as f:
    content = f.read()

# Delete from '    echo -e "\e[1;34m[INFO] Menunggu container MISP merespons (Smart Polling)...\e[0m"'
# down to 'echo -e "\e[1;32mMISP deployment initiated.\e[0m"'

start_marker = r'    echo -e "\\e\[1;34m\[INFO\] Menunggu container MISP merespons \(Smart Polling\)\.\.\.\\e\[0m"'
end_marker = r'        if \[ -n "\$MISP_MODULES" \]; then\n            sudo docker restart "\$MISP_MODULES" >/dev/null 2>&1 \|\| \\\n                echo -e "\\e\[1;33m⚠️ \[WARN\] Gagal restart \$MISP_MODULES\. Lanjut\.\\e\[0m"\n        fi\n    fi'

# Using a generic regex to delete that entire chunk since it's just leftover garbage
cleaned_content = re.sub(
    start_marker + r'.*?' + end_marker,
    '',
    content,
    flags=re.DOTALL
)

if cleaned_content != content:
    with open('setup.sh', 'w', encoding='utf-8', newline='\n') as f:
        f.write(cleaned_content)
    print("Garbage cleaned successfully!")
else:
    print("Garbage not found via regex.")
