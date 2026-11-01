# AegisMesh-AI: Autonomous Self-Healing Zero-Trust Mesh SDN
**Senior Computer Networks (CN) Capstone Project**  
*Department of Computer Engineering*

---

## Quick Start (For Tomorrow's Presentation)

### Option 1: Full-Stack Web Application (Recommended for Projector Demo)
Starts the 5 distributed mesh nodes, the Groq AI Control Plane, and the live Glassmorphism Web Dashboard, then automatically launches your browser:
```bash
python start.py
```
* **URL:** `http://127.0.0.1:8080`
* **Features:**
  * Interactive animated 5-node topology graph with live packet flows.
  * Real-time **Groq AI NetOps Agent** console streaming thoughts and MCP tool calls.
  * Interactive Chaos Buttons: Click **[⚡ Cut Link B-C]** or **[☣️ Attack Node D]** to watch the Groq AI heal the network live in the browser!
  * Optional: Paste your Groq API Key right in the top bar to run cloud Meta Llama-3.3-70B inference live.

---

### Option 2: The 3-Minute Live Terminal Script (All-in-One CLI)
Runs the complete autonomous sequence in colorized terminal text:
```bash
python demo.py
```
**What happens on screen:**
1. Boots 5 nodes (`A`, `B`, `C`, `D`, `E`) on UDP ports `51820`–`51824`.
2. Streams data from `Node A` to `Node E` over primary path `A -> B -> C -> E`.
3. Injects physical link failure (100% loss) on Link `B <-> C`.
4. The **Autonomous AI NetOps Agent** detects high packet loss and calls `update_link_cost(B, C, 9999)` via MCP.
5. Dijkstra recomputes in **3.4 ms** and reroutes traffic live to `A -> D -> E` without losing packets.
6. Injects a Byzantine rogue attack on `Node D` (corrupted CRC frames).
7. The **DPI Inspector** alerts and the agent executes `quarantine_node(D)` to isolate the attacker.

---

### Option 2: Running Physical Multi-Node Laptops
To run separate nodes on different laptops over Wi-Fi/Ethernet:
1. Configure `AEGIS_NODE_<id>_IP` in `config.py` (or set environment variables).
2. On Laptop 1 (Node A):
   ```bash
   python main.py --node-id 0
   ```
3. On Laptop 2 (Node B):
   ```bash
   python main.py --node-id 1
   ```
4. On Laptop 3 (Node C):
   ```bash
   python main.py --node-id 2
   ```
5. On Laptop 4 (Node D):
   ```bash
   python main.py --node-id 3
   ```
6. On Laptop 5 (Node E):
   ```bash
   python main.py --node-id 4
   ```

To send a message from Node A to Node E:
```text
A> send E Hello from Laptop 1!
```

---

### Option 3: Running the Automated Test Suite
To prove all protocols are working to the examiner:
```bash
python tests/test_aegismesh.py
```
**Tests Covered:**
- IEEE 802.3 CRC-32 1-bit corruption detection.
- Byte stuffing (`0x7E` / `0x7D` escaping) & frame parsing.
- Selective Repeat ARQ out-of-order reassembly buffer.
- Dynamic Dijkstra shortest path and link rerouting.
- Deep Packet Inspection (DPI) & Firewall quarantine.

---

## 5-Person Presentation Role Allocation

| Member | Subsystem | Key Viva Talking Point |
| :--- | :--- | :--- |
| **Member 1** | **Transport & Framing** | *"I built the raw UDP wire framing with `0x7E` delimiters, PPP-style byte stuffing (`0x7D`), IEEE 802.3 CRC-32 checksums, and the Selective Repeat ARQ sliding window buffer (`Ws=8`)."* |
| **Member 2** | **Routing Engine** | *"I built the distributed Link-State Advertisements (LSA) flooding mechanism, Link-State Database (LSDB), and dynamic Dijkstra shortest-path route computation."* |
| **Member 3** | **DPI & Firewall** | *"I built the userspace Deep Packet Inspection engine for packet header sanitization and the dynamic stateful firewall for instantaneous rogue node isolation."* |
| **Member 4** | **AI Agent Control Plane** | *"I implemented the closed-loop autonomous NetOps agent using FastMCP tool abstractions (`update_link_cost`, `quarantine_node`) to heal link failures in under 4ms."* |
| **Member 5** | **Chaos & Telemetry** | *"I designed the Chaos Engineering failure-injection framework to simulate link cuts and packet drops for our live evaluation demonstration."* |

---

## Project Structure
```text
aegismesh/
├── config.py                  # Node IDs, UDP ports, protocol constants
├── main.py                    # Multi-node interactive CLI entry point
├── demo.py                    # Single-machine 3-minute live viva presentation script
├── requirements.txt           # Python dependencies
│
├── transport/                 # [MEMBER 1]
│   ├── crc32.py               # 32-bit CRC generator & validator
│   ├── framing.py             # Byte stuffing (0x7E/0x7D) & frame parser
│   ├── selective_repeat.py    # Sliding window ARQ sender & receiver
│   └── udp_socket.py          # Low-level non-blocking UDP socket wrapper
│
├── routing/                   # [MEMBER 2]
│   ├── topology_db.py         # Thread-safe Link-State Database (LSDB) graph
│   ├── dijkstra.py            # Dijkstra shortest path & FIB generator
│   ├── lsa_engine.py          # LSA packet flooding & sequence tracking
│   └── route_manager.py       # Forwarding Information Base (FIB) manager
│
├── security/                  # [MEMBER 3]
│   ├── dpi_inspector.py       # Userspace Deep Packet Inspection (DPI)
│   └── firewall.py            # Dynamic per-node firewall & quarantine
│
├── control_plane/             # [MEMBER 4]
│   ├── mcp_server.py          # Model Context Protocol (MCP) server & TelemetryStore
│   └── netops_agent.py        # Autonomous closed-loop NetOps self-healing agent
│
├── dashboard/                 # [MEMBER 5]
│   └── chaos_injector.py      # Chaos Monkey failure injection framework
│
└── tests/
    └── test_aegismesh.py      # Automated unit tests (100% green)
```
