FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download xray-core (for Germany VLESS proxy)
RUN python3 -c "\
import urllib.request, json, zipfile, os; \
req = urllib.request.Request('https://api.github.com/repos/XTLS/Xray-core/releases/latest', headers={'User-Agent': 'Docker'}); \
data = json.loads(urllib.request.urlopen(req).read()); \
url = next(a['browser_download_url'] for a in data['assets'] if a['name'] == 'Xray-linux-64.zip'); \
urllib.request.urlretrieve(url, '/tmp/xray.zip'); \
with zipfile.ZipFile('/tmp/xray.zip') as z: z.extract('xray', '/app/'); \
os.chmod('/app/xray', 0o755); \
os.remove('/tmp/xray.zip'); \
print('[netscope] xray', data['tag_name'], 'installed'); \
"

COPY main.py .
COPY xray-de.json .
COPY start.sh .
RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
