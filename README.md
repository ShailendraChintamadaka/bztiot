# BZTIoT — Blockchain-Based Zero Trust Security Framework for IoT Devices

> **Academic Project** | Based on the research paper: *ZTBlocIOT2026*  
> **Institution:** CVR College of Engineering  
> **Tech Stack:** Spring Boot 4 · React 18 · PostgreSQL · ESP32 (Wokwi) · Hyperledger Besu *(Phase 4)*

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Technology Stack](#3-technology-stack)
4. [The Trust Formula](#4-the-trust-formula)
5. [File-by-File Reference](#5-file-by-file-reference)
   - [Backend (Spring Boot)](#51-backend-spring-boot)
   - [Frontend (React)](#52-frontend-react)
   - [Firmware (ESP32 / Wokwi)](#53-firmware-esp32--wokwi)
6. [Data Flow — End to End](#6-data-flow--end-to-end)
7. [Database Schema](#7-database-schema)
8. [API Reference](#8-api-reference)
9. [How to Run](#9-how-to-run)
10. [Current Status — What Works](#10-current-status--what-works)
11. [Roadmap — Next Phases](#11-roadmap--next-phases)
12. [Base Paper Mapping](#12-base-paper-mapping-ztblockiot2026)

---

## 1. Project Overview

BZTIoT implements a **Zero Trust Security model** for IoT devices, where **no device is trusted by default** — not even after it has successfully authenticated once.

### Core Principle
> *"Never Trust, Always Verify"* — applied continuously, not just at the front door.

Every single MQTT message from every device triggers a full trust evaluation. The device must continuously justify its access through four independent trust dimensions:

| Dimension | Symbol | Weight | What it measures |
|-----------|--------|--------|-----------------|
| Identity | I | 35% | Was the device authenticated? How recently? How many failures? |
| Behavioral | B | 30% | Is it behaving normally right now? Rate abuse? Replay attacks? |
| Historical | H | 15% | What is its security violation record in the past 60 minutes? |
| Security State | S | 20% | Is it revoked? Quarantined? Firmware hash match? |

The result is a **composite trust score (0–100)** that maps to one of four access decisions:

| Score | Decision | Effect |
|-------|----------|--------|
| ≥ 80 | **ALLOW** | Sensor data saved, full access |
| ≥ 60 | **RESTRICT** | Data saved with elevated monitoring + alert logged |
| ≥ 40 | **QUARANTINE** | Data dropped, device status changed, event logged |
| < 40 | **DENY** | Data dropped, security event logged |

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PHASE 1 & 2 (CURRENT)                        │
│                                                                      │
│  ┌──────────┐   ECDSA      ┌─────────────────────────────────────┐ │
│  │  Wokwi   │ ──────────▶  │       Spring Boot Backend           │ │
│  │  ESP32   │  challenge/  │  ┌───────────┐  ┌────────────────┐  │ │
│  │  DHT22   │  verify      │  │Trust Engine│  │ MQTT Subscriber│  │ │
│  └──────────┘              │  │  (ZT Core) │◀─│  (iot/+/temp) │  │ │
│       │                    │  └─────┬──────┘  └────────────────┘  │ │
│       │ MQTT publish       │        │                               │ │
│       ▼                    │        ▼                               │ │
│  ┌──────────────┐          │  ┌─────────────┐                      │ │
│  │test.mosquitto│          │  │  PostgreSQL  │                      │ │
│  │  .org:1883   │          │  │  bztiotdb    │                      │ │
│  └──────────────┘          │  └─────────────┘                      │ │
│                            └──────────────┬──────────────────────── ┘ │
│                                           │ REST API                   │
│                            ┌──────────────▼──────────────────────── ┐ │
│                            │       React Dashboard                   │ │
│                            │  localhost:5173                         │ │
│                            └────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     PHASE 4 (PLANNED)                                │
│                                                                      │
│  Spring Boot ──▶ Web3j ──▶ Hyperledger Besu (QBFT 4-node)          │
│                            Solidity Smart Contract                   │
│                            • recordTrustEvent(deviceCode, score,     │
│                              decision, ipfsHash)                     │
│                            • getTrustHistory(deviceCode)             │
│                            • revokeDevice(deviceCode)                │
└─────────────────────────────────────────────────────────────────────┘
```

### Deployment (Development)

```
WSL Ubuntu:
  ├── PostgreSQL 5432 (bztiotdb)
  ├── Spring Boot :8080
  └── ngrok http --scheme=http 8080  →  http://xyz.ngrok-free.app

Windows Browser:
  ├── React Vite Dev Server :5173
  └── Wokwi cloud (wokwi.com/projects/476751737104171009)
```

---

## 3. Technology Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Backend | Spring Boot | 4.1.1 | REST API + MQTT subscriber + Trust Engine |
| ORM | Hibernate / Spring Data JPA | 7.4.5 | Database access, schema management |
| Security | Spring Security | 6.x | Session auth for dashboard, permit auth endpoints |
| MQTT | Eclipse Paho + Spring Integration | — | Subscribe to `iot/+/temperature` |
| Database | PostgreSQL | 17 | All persistent data |
| Frontend | React + Vite | 18 / 6 | Admin dashboard SPA |
| Routing | React Router | v6 | Client-side routing |
| Icons | Lucide React | — | UI icons |
| Firmware | Arduino C++ (ESP32) | — | Sensor + auth + MQTT publish |
| Crypto (FW) | mbedTLS | 3.x | ECDSA P-256 signing |
| Simulation | Wokwi | — | Cloud ESP32 + DHT22 simulation |
| Tunnel | ngrok | 3.x | Expose Spring Boot to Wokwi cloud |
| Build | Maven Wrapper | 3.x | `./mvnw spring-boot:run` |
| Java | OpenJDK | 17 | Backend runtime |

---

## 4. The Trust Formula

Directly from the paper **ZTBlocIOT2026**:

$$T = w_1 \cdot I + w_2 \cdot B + w_3 \cdot H + w_4 \cdot S$$

Default weights (configurable in `application.yaml`):

| Weight | Value | Rationale |
|--------|-------|-----------|
| w1 (Identity) | 0.35 | Authentication is the strongest single signal |
| w2 (Behavioral) | 0.30 | Real-time behavior is highly relevant |
| w3 (Historical) | 0.15 | Past record matters but decays |
| w4 (Security State) | 0.20 | Firmware integrity and revocation status |

### Identity Score (I) — Decay over time

| Condition | Score |
|-----------|-------|
| ≥5 consecutive auth failures | 0 |
| 3-4 failures | 20 |
| 1-2 failures | 50 |
| Never authenticated | 10 |
| Authenticated < 30 min ago | 100 |
| 30–60 min ago | 85 |
| 60–120 min ago | 70 |
| > 2 hours ago | 55 |

### Behavioral Score (B) — Deductions

| Anomaly | Deduction |
|---------|-----------|
| Rate limit exceeded (>20 msg/min) | -40 |
| Replay attack detected | -50 |
| Unauthorized topic attempt | -30 |

### Historical Score (H) — Recent violations (60-min window)

| Violations | Score |
|------------|-------|
| 0 | 100 |
| 1 | 75 |
| 2 | 50 |
| 3–5 | 25 |
| ≥6 | 0 |

### Security State Score (S)

| State | Score |
|-------|-------|
| REVOKED | 0 |
| QUARANTINED | 10 |
| Firmware hash mismatch | 30 |
| Normal | 100 |

---

## 5. File-by-File Reference

### 5.1 Backend (Spring Boot)

```
src/main/java/edu/cvr/bztiot/
├── BztiotApplication.java                  — Spring Boot entry point (@SpringBootApplication)
│
├── config/
│   ├── SecurityConfig.java                 — Spring Security: session auth for dashboard,
│   │                                          permitAll for /api/devices/auth/**, CORS config
│   └── MqttConfig.java                     — MQTT subscriber: connects to test.mosquitto.org,
│                                             subscribes iot/+/temperature, parses JSON payload,
│                                             calls TrustEvaluationService, saves SensorReading
│
├── controller/
│   ├── AuthController.java                 — GET /api/auth/me (session check for frontend)
│   ├── DashboardController.java            — GET /api/dashboard/stats (device counts, risk dist.)
│   │                                          GET /api/dashboard/events (last 20 security events)
│   ├── DeviceAuthController.java           — GET /api/devices/auth/challenge/{deviceCode}
│   │                                          POST /api/devices/auth/verify
│   ├── DeviceController.java               — Full device CRUD: register, list, update, delete,
│   │                                          status change, public key management
│   └── SecurityController.java             — GET /api/security/events (all events, top 20)
│                                              GET /api/security/events/{deviceCode}
│                                              GET /api/security/history/{deviceCode}
│                                              GET /api/security/decisions/{deviceCode}
│
├── dto/
│   ├── AuthChallengeResponse.java          — { "challenge": "<base64 nonce>" }
│   ├── AuthVerifyRequest.java              — { "deviceCode": "...", "signature": "<base64>" }
│   ├── DeviceRegistrationRequest.java      — { deviceCode, publicKey, deviceType,
│   │                                           expectedFirmwareHash }
│   ├── DeviceStatusRequest.java            — { status: "ACTIVE|QUARANTINED|REVOKED" }
│   └── DeviceUpdateRequest.java            — Partial device update DTO
│
├── model/
│   ├── Device.java                         — @Entity devices: deviceCode, publicKey,
│   │                                          trustScore, status, lastAuthAt, authFailureCount
│   ├── DeviceStatus.java                   — Enum: ACTIVE, QUARANTINED, REVOKED
│   ├── AccessDecision.java                 — Enum: ALLOW, RESTRICT, QUARANTINE, DENY
│   ├── AccessDecisionLog.java              — @Entity access_decision_log: per-message decisions
│   ├── AccessDecisionLog.java              — @Entity access_decision_log
│   ├── SecurityEvent.java                  — @Entity security_events: audit trail of anomalies
│   ├── SensorReading.java                  — @Entity sensor_readings: temperature/humidity data
│   └── TrustScoreHistory.java              — @Entity trust_score_history: I/B/H/S snapshots
│
├── repository/                             — Spring Data JPA repositories (all extend
│   ├── DeviceRepository.java                 JpaRepository — CRUD + custom queries)
│   ├── SensorReadingRepository.java
│   ├── SecurityEventRepository.java
│   ├── TrustScoreHistoryRepository.java
│   └── AccessDecisionLogRepository.java
│
└── service/
    ├── TrustEvaluationService.java         — ★ ORCHESTRATOR: Called per MQTT message.
    │                                          Collects signals → builds TrustInputs →
    │                                          calculates score → makes decision →
    │                                          persists history → returns EvaluationResult
    ├── RiskScoreCalculator.java            — Pure function: T = w1*I + w2*B + w3*H + w4*S
    │                                          No DB access, fully unit-testable
    ├── AccessPolicyService.java            — Maps score + hard gates → AccessDecision
    │                                          Hard gates: REVOKED, REPLAY DETECTED
    ├── DeviceBehaviorMonitor.java          — In-memory sliding-window rate limiter,
    │                                          replay detector, unauthorized topic tracker
    ├── AuthenticationService.java          — ECDSA challenge generation + signature verification
    │                                          SHA256withECDSA, 60-second challenge TTL
    ├── DeviceService.java                  — Device CRUD business logic
    ├── SecurityEventService.java           — Helper to record typed security events
    └── TrustInputs.java                   — Immutable value object (Builder pattern):
                                              all signals for one trust evaluation
```

### 5.2 Frontend (React)

```
frontend/src/
├── api.js                   — Axios base URL = '' (uses Vite proxy → :8080)
├── App.jsx                  — React Router routes, auth state, ProtectedRoute wrapper
├── main.jsx                 — ReactDOM.createRoot entry point
│
├── components/
│   ├── Layout.jsx           — Sidebar nav, top bar, outlet container
│   ├── Logo.jsx             — BZTIoT brand logo component
│   ├── ProtectedRoute.jsx   — Redirects to /login if not authenticated
│   └── UI.jsx               — Reusable: Badge, Card, StatCard, Table components
│
├── pages/
│   ├── Landing.jsx          — Public landing page (unauthenticated)
│   ├── Login.jsx            — POST /perform_login form
│   ├── Dashboard.jsx        — Real-time overview: device stats + security events
│   │                          Auto-refreshes every 15s. Fetches /api/dashboard/*
│   ├── Devices.jsx          — Device list table with trust scores, status badges
│   ├── DeviceDetail.jsx     — Per-device: I/B/H/S bars, events, trust history,
│   │                          access decisions. Route: /devices/:deviceCode
│   ├── RegisterDevice.jsx   — Form: POST /api/devices/register
│   └── SecurityEvents.jsx   — Security monitoring with severity filters (ALL/CRITICAL/HIGH/...)
│                              Auto-refreshes every 10s
│
└── styles.css               — Global dark theme CSS
```

### 5.3 Firmware (ESP32 / Wokwi)

```
firmware/sketch.ino          — Full ESP32 firmware (570 lines)

What it does (in order):
  1. setup_wifi()             Connect to Wokwi-GUEST WiFi
  2. setup_time()             Sync NTP (pool.ntp.org) for timestamps
  3. computeFirmwareHash()    SHA-256("BZT-IoT-ESP32-v1.0.0") → hex string
  4. ensureAuthenticated()    Zero Trust auth: challenge → sign → verify (3 retries)
     ├── GET  BACKEND_URL/api/devices/auth/challenge/ESP32_001
     │         → receives Base64 nonce (32 bytes)
     ├── signChallenge()     mbedTLS: SHA256(nonce) → ECDSA P-256 DER signature
     └── POST BACKEND_URL/api/devices/auth/verify
               body: { "deviceCode": "ESP32_001", "signature": "<base64 DER>" }
               expect: { "status": "AUTHENTICATED" }
  5. loop() every 5 seconds:
     ├── Re-auth if 30 min elapsed (Zero Trust: no permanent access)
     ├── Read DHT22 (temperature + humidity)
     └── Publish to iot/ESP32_001/temperature via test.mosquitto.org:1883
         ONLY if isAuthenticated == true

Security notes (viva points):
  • Private key is embedded (SIMULATION ONLY). Real deployment: ESP32 eFuse or ATECC608B.
  • Uses WiFiClient (plain HTTP) with ngrok HTTP tunnel — Wokwi cloud cannot do TLS.
  • Firmware hash is SHA-256 of a constant string (concept demo, not real integrity check).
  • Re-authentication every 30 minutes demonstrates Zero Trust continuous verification.
```

---

## 6. Data Flow — End to End

```
Step 1: Device Registration (one-time, by admin)
  Admin UI → POST /api/devices/register
           → Device stored with publicKey, expectedFirmwareHash, status=ACTIVE, trustScore=50

Step 2: Firmware Auth (at ESP32 boot)
  ESP32 → GET  /api/devices/auth/challenge/ESP32_001
        ← { "challenge": "base64_nonce" }
  ESP32 → (mbedTLS) sign nonce with ECDSA private key → DER signature → Base64
  ESP32 → POST /api/devices/auth/verify  { deviceCode, signature }
        → AuthenticationService.verifyResponse():
            • Load device from DB
            • Remove & validate pending challenge (60s TTL)
            • Signature.verify(SHA256withECDSA, publicKey, nonce)
            • If valid: trustScore += 30, lastAuthAt = now, authFailureCount = 0
        ← { "status": "AUTHENTICATED" }

Step 3: Sensor Publishing (every 5 seconds)
  ESP32 → MQTT publish to test.mosquitto.org:1883
          topic: iot/ESP32_001/temperature
          payload: { "deviceCode":"ESP32_001", "temperature":26.0,
                     "humidity":39.3, "firmwareHash":"b4478d...", "timestamp":1794292202000 }

Step 4: Trust Evaluation (per message, in Spring Boot)
  MQTT broker → Spring Integration → MqttConfig.handler()
  handler():
    1. Parse JSON payload
    2. TrustEvaluationService.evaluate(deviceCode, firmwareHash, timestamp)
       a. Load device from DB
       b. DeviceBehaviorMonitor: rate check, replay check, topic check
       c. Build TrustInputs
       d. RiskScoreCalculator.calculate() → T = 0.35I + 0.30B + 0.15H + 0.20S
       e. AccessPolicyService.decide() → ALLOW/RESTRICT/QUARANTINE/DENY
       f. Update device.trustScore, device.lastSeenAt in DB
       g. Save TrustScoreHistory snapshot
       h. Save AccessDecisionLog
    3. If decision blocks → return (do NOT save sensor reading)
    4. If RESTRICT → log RESTRICTED_ACCEPT event
    5. Save SensorReading (temperature row + humidity row)

Step 5: Dashboard (React, auto-refresh)
  GET /api/dashboard/stats  → device counts, risk distribution
  GET /api/dashboard/events → last 20 security events
  GET /api/security/events  → Security Monitoring page data
  GET /api/security/history/ESP32_001 → Trust score I/B/H/S history
```

---

## 7. Database Schema

```sql
-- Device registry
CREATE TABLE devices (
  id                    UUID PRIMARY KEY,
  device_code           VARCHAR UNIQUE NOT NULL,
  public_key            TEXT UNIQUE NOT NULL,
  expected_firmware_hash TEXT,
  device_type           VARCHAR NOT NULL,
  device_status         VARCHAR NOT NULL,     -- ACTIVE / QUARANTINED / REVOKED
  current_risk_score    INTEGER,              -- stores trust score (0–100)
  last_auth_at          TIMESTAMPTZ,
  auth_failure_count    INTEGER NOT NULL DEFAULT 0,
  registered_at         TIMESTAMPTZ NOT NULL,
  last_seen_at          TIMESTAMPTZ
);

-- Raw sensor readings
CREATE TABLE sensor_readings (
  id                    BIGINT PRIMARY KEY,
  device_id             UUID REFERENCES devices(id),
  metric_type           VARCHAR NOT NULL,     -- "temperature" or "humidity"
  metric_value          DOUBLE PRECISION NOT NULL,
  reported_firmware_hash VARCHAR,
  device_timestamp      TIMESTAMPTZ,
  received_at           TIMESTAMPTZ NOT NULL
);

-- Security event audit trail
CREATE TABLE security_events (
  id                BIGINT PRIMARY KEY,
  device_code       VARCHAR NOT NULL,
  event_type        VARCHAR NOT NULL,         -- AUTH_SUCCESS, AUTH_FAILED, QUARANTINE_ENFORCED, etc.
  severity          VARCHAR NOT NULL,         -- INFO / LOW / MEDIUM / HIGH / CRITICAL
  detail            TEXT,
  trust_score_before INTEGER,
  trust_score_after  INTEGER,
  access_decision   VARCHAR,
  created_at        TIMESTAMPTZ NOT NULL
);

-- Trust score component snapshots (per MQTT message)
CREATE TABLE trust_score_history (
  id                  BIGINT PRIMARY KEY,
  device_code         VARCHAR NOT NULL,
  identity_score      INTEGER,
  behavioral_score    INTEGER,
  historical_score    INTEGER,
  security_state_score INTEGER,
  trust_score         INTEGER,
  access_decision     VARCHAR,
  trigger_event       VARCHAR,
  recorded_at         TIMESTAMPTZ NOT NULL
);

-- Per-message access decisions
CREATE TABLE access_decision_log (
  id          BIGINT PRIMARY KEY,
  device_code VARCHAR NOT NULL,
  operation   VARCHAR,                        -- "PUBLISH:iot/ESP32_001/temperature"
  trust_score INTEGER,
  decision    VARCHAR,                        -- ALLOW / RESTRICT / QUARANTINE / DENY
  reason      TEXT,
  enforced    BOOLEAN,
  decided_at  TIMESTAMPTZ NOT NULL
);
```

---

## 8. API Reference

### Public (no auth required)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/perform_login` | Form login: `username=admin&password=admin123` |
| GET | `/api/devices/auth/challenge/{deviceCode}` | Returns Base64 nonce for ECDSA signing |
| POST | `/api/devices/auth/verify` | Submits signed challenge, updates trust score |

### Protected (session cookie required)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/me` | Current session info |
| GET | `/api/devices` | List all devices |
| POST | `/api/devices/register` | Register new device |
| PATCH | `/api/devices/{id}/status` | Change device status |
| DELETE | `/api/devices/{id}` | Remove device |
| GET | `/api/dashboard/stats` | Device count + risk distribution |
| GET | `/api/dashboard/events` | Last 20 security events |
| GET | `/api/security/events` | All security events (top 20) |
| GET | `/api/security/events/{deviceCode}` | Events for one device |
| GET | `/api/security/history/{deviceCode}` | Trust score I/B/H/S history |
| GET | `/api/security/decisions/{deviceCode}` | Access decisions for a device |

---

## 9. How to Run

### Prerequisites
- WSL2 Ubuntu with: Java 17, Maven, Node.js 18+, PostgreSQL 17, ngrok
- Windows: Wokwi account, pgAdmin 4 (optional)

### Step 1 — Start PostgreSQL (WSL)
```bash
sudo service postgresql start
psql -U postgres -c "CREATE DATABASE bztiotdb;" 2>/dev/null || true
```

### Step 2 — Start Backend (WSL)
```bash
cd /mnt/c/Users/shail/.gemini/antigravity-ide/scratch/bztiot
./mvnw spring-boot:run
# Wait for: "Started BztiotApplication in X seconds"
```

### Step 3 — Start Frontend (WSL, new terminal)
```bash
cd /mnt/c/Users/shail/.gemini/antigravity-ide/scratch/bztiot/frontend
npm run dev
# Open: http://localhost:5173
# Login: admin / admin123
```

### Step 4 — Start ngrok (WSL, new terminal)
```bash
ngrok http --scheme=http 8080
# Note the http:// URL (e.g., http://cb69-103-88-239-114.ngrok-free.app)
```

### Step 5 — Register Device (browser)
1. Go to `http://localhost:5173/devices/register`
2. Device Code: `ESP32_001`
3. Public Key: contents of `firmware/device_public.pem`
4. Device Type: `Temperature Sensor`
5. Expected Firmware Hash: `b4478d9f80c111ba73f14e6c1bf9f665ee1652ef93de34e56ab97ca3544de4de`

### Step 6 — Run Wokwi Simulation
1. Open: `wokwi.com/projects/476751737104171009`
2. Update line 62 in `sketch.ino`: `const char* BACKEND_URL = "http://YOUR-NGROK-URL";`
3. Click ▶ Play
4. Expected Serial Monitor output:
   ```
   [AUTH] ✓ Device authenticated successfully.
   [MQTT] Published: {"deviceCode":"ESP32_001","temperature":26.0,...}
   ```

### Step 7 — View in Dashboard
- Overview: `http://localhost:5173`
- Devices: `http://localhost:5173/devices`
- Security Monitoring: `http://localhost:5173/security`

### Step 8 — Verify in DB (WSL)
```bash
psql -U postgres -d bztiotdb -c "SELECT metric_type, metric_value, received_at FROM sensor_readings ORDER BY received_at DESC LIMIT 10;"
```

---

## 10. Current Status — What Works

| Feature | Status |
|---------|--------|
| ESP32 WiFi + NTP | ✅ Working |
| Firmware SHA-256 hash | ✅ Working |
| ECDSA challenge-response auth | ✅ Working |
| MQTT publish (authenticated only) | ✅ Working |
| Spring Boot MQTT subscriber | ✅ Working |
| Trust formula T = w1I + w2B + w3H + w4S | ✅ Working |
| Access decisions (ALLOW/RESTRICT/QUARANTINE/DENY) | ✅ Working |
| Behavioral monitoring (rate, replay, topic) | ✅ Working |
| PostgreSQL persistence (all 5 tables) | ✅ Working |
| React dashboard with real data | ✅ Working |
| Security Monitoring with severity filters | ✅ Working |
| Device detail page (trust breakdown) | ✅ Working |
| Re-authentication every 30 minutes | ✅ Working |
| ngrok HTTP tunnel (Wokwi → Spring Boot) | ✅ Working |
| Blockchain audit trail (Hyperledger Besu) | ⏳ Phase 4 |
| Multi-sensor support | ⏳ Phase 3 |
| Access policy enforcement API | ⏳ Phase 3 |

---

## 11. Roadmap — Next Phases

### Phase 3 — Multi-Sensor + Policy Enforcement (Next)

#### 3A — Multi-Sensor Support
**Current limitation:** Only one topic `iot/+/temperature` is subscribed. Each MQTT message can carry multiple metrics (temperature + humidity) but all go to the same topic.

**Changes needed:**

1. **application.yaml** — Change topic to wildcard:
   ```yaml
   mqtt:
     topic: iot/#    # subscribe to ALL sub-topics: iot/+/temperature, iot/+/humidity, iot/+/pressure
   ```

2. **MqttConfig.java** — Extract `metricType` from topic (not from JSON field):
   ```java
   // Currently: iterates JSON fields (temperature, humidity)
   // Better: topic-based routing
   // iot/ESP32_001/temperature → metric_type = "temperature"
   // iot/ESP32_002/pressure   → metric_type = "pressure"
   ```

3. **firmware/sketch.ino** — Support multiple sensors:
   - Add DHT11 on second pin for humidity-only sensor
   - Publish separate topics: `iot/ESP32_001/temperature`, `iot/ESP32_001/humidity`
   - Add BMP280 support for pressure (I2C)

4. **DeviceBehaviorMonitor** — Per-metric rate limiting:
   - Current: 20 msg/min total
   - Needed: per-topic rate limits (temperature: 12/min, vibration: 60/min)

5. **Device Registration** — Add `allowedTopics` field to Device entity:
   ```java
   @Column(name = "allowed_topics")
   private String allowedTopics;  // "iot/ESP32_001/temperature,iot/ESP32_001/humidity"
   ```

6. **No architecture change needed** — the trust engine is already sensor-agnostic.

#### 3B — Access Policy Enforcement API
Currently: `AccessPolicyService` decides, but only the MQTT handler enforces it.

**Add enforcement for other operations:**

```java
// New endpoint: devices can query their own policy
GET /api/policy/check?deviceCode=ESP32_001&operation=READ:sensor_data
→ { "decision": "ALLOW", "trustScore": 85, "reason": "..." }

// Policy matrix (to implement)
Operation          | ALLOW | RESTRICT      | QUARANTINE | DENY
-------------------+-------+---------------+------------+-------
Publish sensor     |  Yes  | Yes (logged)  | No         | No
Read own history   |  Yes  | Yes           | No         | No
Firmware update    |  Yes  | No            | No         | No
Subscribe to other |  No   | No            | No         | No
```

#### 3C — Device-to-Device Trust
Currently: only device → server trust. The paper mentions D2D trust.

```java
// New: devices can query trust score of peer devices
GET /api/devices/{deviceCode}/trust-score  (admin + device-with-token)
```

---

### Phase 4 — Blockchain Integration (Hyperledger Besu)

#### Why Blockchain?
The paper's key argument: PostgreSQL audit logs can be tampered with by an insider. Blockchain provides **tamper-proof, distributed** audit trail where:
- Trust events are **immutable** once written
- **Any node** can verify the history without trusting any single server
- Device revocation is **consensus-driven** (not a single-admin action)

#### Architecture Addition

```
Spring Boot (existing)
    │
    ├── TrustEvaluationService.evaluate() [existing]
    │        │
    │        ▼
    │   BlockchainAuditService.java [NEW]
    │        │
    │        ▼
    │   Web3j (Java library) [NEW dependency]
    │        │
    │        ▼
    │   ZeroTrustAudit.sol [Solidity smart contract]
    │        │
    │        ▼
    │   Hyperledger Besu (QBFT 4-node network) [NEW]
```

#### What Data Goes to Blockchain

```solidity
// ZeroTrustAudit.sol
struct TrustEvent {
    string  deviceCode;        // "ESP32_001"
    uint256 trustScore;        // 0–100
    string  decision;          // "ALLOW"/"RESTRICT"/"QUARANTINE"/"DENY"
    uint256 identityScore;     // I component
    uint256 behavioralScore;   // B component
    uint256 historicalScore;   // H component
    uint256 securityStateScore;// S component
    string  firmwareHash;      // reported hash
    uint256 timestamp;         // epoch seconds
    bytes32 ipfsHash;          // CID of full payload (optional)
}
```

**What stays in PostgreSQL (fast queries):**
- Raw sensor readings (high volume, no audit need)
- Session state, device registration (mutable operational data)

**What goes to Blockchain (immutable audit):**
- Every trust evaluation result (score + decision + all 4 components)
- Device registration events
- Device revocation events
- Authentication success/failure events

#### Hyperledger Besu Setup

```bash
# 4-node QBFT private network
besu --genesis-file=genesis.json
     --network-id=1337
     --rpc-http-enabled
     --rpc-http-port=8545

# 4 validator nodes: node1:8545, node2:8546, node3:8547, node4:8548
```

#### Java Integration (Web3j)

```java
// pom.xml additions needed
<dependency>
    <groupId>org.web3j</groupId>
    <artifactId>core</artifactId>
    <version>4.12.0</version>
</dependency>

// BlockchainAuditService.java [NEW]
@Service
public class BlockchainAuditService {
    private final ZeroTrustAudit contract;  // Web3j generated wrapper

    public void recordTrustEvent(String deviceCode, TrustComponents components,
                                  AccessDecision decision, String firmwareHash) {
        contract.recordEvent(
            deviceCode,
            BigInteger.valueOf(components.trustScore()),
            decision.name(),
            BigInteger.valueOf(components.identityScore()),
            // ... etc
        ).send();  // synchronous, or use sendAsync()
    }

    public void revokeDevice(String deviceCode) {
        contract.revokeDevice(deviceCode).send();
    }

    public List<TrustEvent> getTrustHistory(String deviceCode) {
        return contract.getTrustHistory(deviceCode).send();
    }
}
```

#### Dashboard Integration (React)
- **Blockchain Audits page** (`/blockchain`): Real smart contract events
- Each row: txHash, blockNumber, trustScore, decision, timestamp
- Link to Besu explorer (BlockScout)

#### Files to Create in Phase 4

```
contracts/
├── ZeroTrustAudit.sol              — Main smart contract
├── compile.sh                      — solc compilation script
└── ZeroTrustAudit.abi              — ABI for Web3j wrapper generation

besu/
├── genesis.json                    — QBFT genesis with 4 validators
├── node1/ node2/ node3/ node4/     — Each node's data directory
└── start-network.sh                — Start all 4 nodes

src/main/java/edu/cvr/bztiot/
├── service/BlockchainAuditService.java
├── config/BlockchainConfig.java
└── controller/BlockchainController.java  — /api/blockchain/events/{deviceCode}

frontend/src/pages/
└── BlockchainAudits.jsx            — Replace hardcoded mock with real data
```

---

### Phase 5 — Production Hardening (Future)

| Feature | Description |
|---------|-------------|
| **Redis behavior store** | Replace in-memory DeviceBehaviorMonitor with Redis for multi-instance |
| **Device sequence numbers** | Add `seqNo` to firmware payload for true replay detection |
| **Hardware secure element** | ATECC608B for private key storage on real ESP32 |
| **MQTT TLS** | Switch from `test.mosquitto.org` to private broker with TLS |
| **Certificate-based MQTT auth** | X.509 device certs instead of challenge-response |
| **Alert notifications** | Email/Slack webhook on CRITICAL events |
| **Automated trust recovery** | Reset trust score after clean period automatically |
| **Multi-admin roles** | RBAC: viewer / operator / administrator |
| **Rate limit configuration UI** | Dashboard controls for threshold tuning |
| **IPFS sensor data** | Pin large sensor blobs to IPFS, store CID on blockchain |

---

## 12. Base Paper Mapping (ZTBlocIOT2026)

| Paper Concept | Implementation |
|--------------|----------------|
| Zero Trust IoT framework | `TrustEvaluationService` — evaluates every MQTT message |
| Trust score formula T = w1I + w2B + w3H + w4S | `RiskScoreCalculator.calculate()` |
| Identity factor (I) with time decay | `computeIdentityScore()` — 100→55 over 2h |
| Behavioral factor (B) | `computeBehavioralScore()` + `DeviceBehaviorMonitor` |
| Historical factor (H) with violation window | `computeHistoricalScore()` — 60-min window |
| Security state factor (S) | `computeSecurityStateScore()` — revocation, firmware |
| Access policy thresholds | `AccessPolicyService.decide()` — 80/60/40 thresholds |
| Hard security gates | `AccessPolicyService` — REVOKED + REPLAY gates |
| ECDSA challenge-response authentication | `AuthenticationService` + firmware `signChallenge()` |
| Blockchain immutable audit | ⏳ Phase 4 — Hyperledger Besu + Solidity |
| Continuous re-authentication | Firmware re-auth every 30 min + trust decay |
| Device revocation | `DeviceStatus.REVOKED` — hard DENY gate |

---

## Credentials

| Service | Username | Password |
|---------|----------|----------|
| Dashboard | `admin` | `admin123` |
| PostgreSQL | `postgres` | `2005` |
| Wokwi project | — | `wokwi.com/projects/476751737104171009` |

---

*Generated: November 2026 | BZTIoT v1.0 — Phase 2 Complete*

