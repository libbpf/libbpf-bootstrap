// server.ts
const server = Bun.serve({
  port: 3000,
  fetch(req, server) {
    if (server.upgrade(req)) return;
    return new Response(Bun.file("index.html"));
  },
  websocket: {
    open(ws) { ws.subscribe("alerts"); },
    message(ws, msg) {},
  },
});

console.log("🚀 Dashboard: http://localhost:3000");

// PIPE: Read Python alerts from stdin and push to browser
const decoder = new TextDecoder();
for await (const chunk of Bun.stdin.stream()) {
  const text = decoder.decode(chunk);
  server.publish("alerts", text);
}
