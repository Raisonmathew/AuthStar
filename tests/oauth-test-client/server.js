const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 8080;
const HTML_FILE = path.join(__dirname, 'index.html');

const server = http.createServer((req, res) => {
  // Serve the same index.html for all paths (SPA-style)
  const html = fs.readFileSync(HTML_FILE, 'utf-8');
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
});

server.listen(PORT, () => {
  console.log(`OAuth test client running at http://localhost:${PORT}`);
  console.log('Press Ctrl+C to stop');
});
