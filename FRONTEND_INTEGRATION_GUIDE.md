# 🛡️ Guía de Integración Frontend para KILLAgent
**Zero Trust Hardware Anchor & PKCS#11 DNIe WebSocket Protocol**  
*Plataforma Ch'aska — Gestión Documental y Firma Digital*

---

## 1. Introducción y Arquitectura de Comunicación

`KILLAgent` es un daemon local de escritorio que se ejecuta en la estación de trabajo del usuario (Windows). Su propósito es actuar como **ancla física de hardware criptográfico**, comunicándose con el navegador web (React SPA) mediante un canal WebSocket local exclusivo en bucle invertido (`127.0.0.1:3000`).

```
┌──────────────────────────┐                  ┌────────────────────────────────────────┐
│  Navegador Web (SPA)     │                  │  Estación de Trabajo (KILLAgent)       │
│  React / TypeScript      │                  │  Java 21 LTS (Loopback 127.0.0.1:3000) │
│                          │  ws:// / wss://  │                                        │
│  • Ch'aska Web App       │◄────────────────►│  • Servidor WebSocket Loopback         │
│  • Solicitud de Retos    │                  │  • Modal PIN Anti-Keylogger (Zero-Str) │
│  • Escucha de Kill-Switch│                  │  • Middleware IDEMIA PKCS#11           │
└──────────────────────────┘                  └──────────────────┬─────────────────────┘
                                                                 │ WinSCard / PC/SC
                                                                 ▼
                                                      [ Lector USB + DNIe 3.0/2.0 ]
```

### Invariantes Fundamentales para el Frontend
1. **Zero Network Traversal de PIN:** El frontend **NUNCA** solicita ni gestiona el PIN del DNIe del usuario. El PIN se ingresa **exclusivamente** en el modal seguro del agente de escritorio protegido contra capturas de pantalla y keyloggers.
2. **Loopback Estricto:** La URL de conexión siempre apunta a `127.0.0.1` o `localhost`. Nunca a direcciones IP de red local ni dominios externos.
3. **Validación de Origen (Anti-CSWSH):** El agente valida la cabecera `Origin` enviada por el navegador contra su lista blanca (`ALLOWED_ORIGINS`). Si tu origen web (ej. `http://localhost:5173` o `https://app.chaska.pe`) no está en el `.env` del agente, la conexión será rechazada inmediatamente.

---

## 2. Endpoints de Conexión

| Entorno | Protocolo / URL | Descripción |
| :--- | :--- | :--- |
| **Desarrollo Local** | `ws://127.0.0.1:3000` | Comunicación WebSocket estándar sin cifrar sobre loopback. |
| **Producción Web (HTTPS)** | `wss://127.0.0.1:3000` | Canal seguro WSS (TLS 1.3/1.2). Requiere certificado de loopback auto-aprovisionado o de confianza. |

> [!IMPORTANT]
> Si tu aplicación web se sirve sobre **HTTPS**, los navegadores modernos (Chrome, Edge, Firefox) exigen **`wss://`** debido a las políticas de Mixed Content.

---

## 3. Ciclo de Vida de la Conexión y Handshake

### 3.1 Evento de Bienvenida: `CONNECTION_ESTABLISHED`
Inmediatamente después de que el navegador completa el handshake con un `Origin` válido, el agente envía **sin solicitud previa** el mensaje de estado inicial:

```json
{
  "type": "CONNECTION_ESTABLISHED",
  "wsConnectionId": "ws-killagent-9921b-4f81",
  "version": "1.0.0",
  "hardwareStatus": {
    "readerPresent": true,
    "cardPresent": true,
    "readerName": "Identiv uTrust 2700 R Smart Card Reader 0",
    "cardType": "DNIE_3_0",
    "isMock": false
  }
}
```

#### Valores de `cardType`:
* `"NONE"`: No hay tarjeta insertada.
* `"DNIE_3_0"`: DNI Electrónico 3.0 (chip IDEMIA Cosmo).
* `"DNIE_2_0"`: DNI Electrónico 2.0 (chip Bit4id).
* `"UNKNOWN"`: Tarjeta inteligente no reconocida como DNIe.

---

## 4. Eventos Push en Tiempo Real (Kill-Switch Hardware)

El agente emite eventos proactivos (unsolicited) cuando el usuario conecta o desconecta el hardware. El frontend debe suscribirse a estos eventos para actualizar la interfaz inmediatamente.

### 4.1 Retiro de Tarjeta: `CARD_REMOVED` *(Disparador del Kill-Switch)*
Se emite en **menos de 10 milisegundos** cuando el usuario retira físicamente el DNIe del lector.

```json
{
  "type": "CARD_REMOVED",
  "timestamp": "2026-11-06T10:15:30.123Z"
}
```

> [!CAUTION]
> **Acción Requerida en el Frontend:**
> 1. Invalidar inmediatamente cualquier estado o token de autenticación temporal de sesión.
> 2. Si el usuario estaba en medio de un flujo de firma, cancelar la operación y mostrar una alerta: *"DNIe retirado. Operación cancelada por seguridad"*.
> 3. Bloquear o desactivar los botones de *"Firmar Documento"* hasta que se vuelva a insertar la tarjeta.

### 4.2 Inserción de Tarjeta: `CARD_INSERTED`
Se emite cuando una tarjeta inteligente física es introducida en la ranura del lector.

```json
{
  "type": "CARD_INSERTED",
  "timestamp": "2026-11-06T10:16:05.456Z",
  "readerName": "Identiv uTrust 2700 R 0"
}
```

---

## 5. Operaciones Criptográficas (Request - Response)

Todas las operaciones siguen un modelo asíncrono con correlación mediante **`requestId`**.

### 5.1 Operación 1: Firma de Reto de Autenticación (`SIGN_AUTH_CHALLENGE`)
Utilizado en el inicio de sesión institucional (Fase 2) y en elevación de privilegios (Step-Up Authentication). Utiliza el **Certificado de Autenticación** del DNIe.

#### 1. Petición del Frontend hacia KILLAgent:
```json
{
  "type": "SIGN_AUTH_CHALLENGE",
  "requestId": "req-auth-1002",
  "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01"
}
```
* **`nonce`**: Cadena hexadecimal de 64 caracteres (o bytes en Base64) provista por el backend de Ch'aska (`GET /api/v1/authentication/challenge`).

#### 2. Comportamiento en la Estación de Trabajo:
El agente despliega sobre la pantalla del usuario el **teclado virtual aleatorizado** solicitando el PIN de autenticación.

#### 3. Respuesta Exitosa de KILLAgent hacia el Frontend:
```json
{
  "type": "SIGN_AUTH_CHALLENGE_RESPONSE",
  "requestId": "req-auth-1002",
  "status": "SUCCESS",
  "payload": {
    "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01",
    "signedNonce": "MEQCIAuW...<Firma RSA Base64>...",
    "clientCertificatePem": "-----BEGIN CERTIFICATE-----\nMIIF...<Certificado RENIEC X.509>...\n-----END CERTIFICATE-----",
    "wsConnectionId": "ws-killagent-9921b-4f81",
    "metadata": {
      "dni": "71234567",
      "fullName": "JUAN PEREZ GARCIA",
      "certificateSerialNumber": "4A12B890F1",
      "validTo": "2028-06-15T23:59:59Z"
    }
  }
}
```

#### 4. Envío al Backend de Ch'aska:
El frontend toma el contenido de `payload` y lo remite vía HTTP POST al backend:
```typescript
await api.post('/api/v1/authentication/sign-in', {
  nonce: payload.nonce,
  signedNonce: payload.signedNonce,
  clientCertificatePem: payload.clientCertificatePem
});
```

---

### 5.2 Operación 2: Firma de Digest de Documento (`SIGN_DOCUMENT_DIGEST`)
Utilizado para el sellado digital de documentos PDF conforme al estándar **PAdES-LTV (Ley N° 27269)**. Utiliza obligatoriamente el **Certificado de No-Repudio / Firma Digital**.

#### 1. Petición del Frontend hacia KILLAgent:
```json
{
  "type": "SIGN_DOCUMENT_DIGEST",
  "requestId": "req-doc-5501",
  "slotId": "b18f8101-5e92-4293-8b7c-7a54911f32a0",
  "documentHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "documentTitle": "Convenio de Cooperación Técnica 2026.pdf",
  "signerRole": "DIRECTOR_LEGAL"
}
```
* **`slotId`**: Identificador único de ranura o sesión de firma provisto por el backend.
* **`documentHash`**: Hash SHA-256 del documento en formato hexadecimal de 64 caracteres.
* **`documentTitle`**: Nombre legible que el agente mostrará al usuario en el modal para su confirmación visual consciente.
* **`signerRole`**: Rol o cargo con el que firma el documento.

#### 2. Respuesta Exitosa de KILLAgent hacia el Frontend:
```json
{
  "type": "SIGN_DOCUMENT_DIGEST_RESPONSE",
  "requestId": "req-doc-5501",
  "status": "SUCCESS",
  "payload": {
    "slotId": "b18f8101-5e92-4293-8b7c-7a54911f32a0",
    "certificateDni": "71234567",
    "documentHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "signatureValue": "Rz1m...<Firma PAdES PKCS#1 v1.5 Base64>...",
    "signerSubjectDn": "CN=JUAN PEREZ GARCIA, SERIALNUMBER=DNI71234567, O=RENIEC, C=PE",
    "certificateSerialNumber": "4A12B890F1",
    "clientCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }
}
```

#### 3. Envío al Backend de Ch'aska:
El frontend remite el resultado al comando de registro de firma del backend:
```typescript
await api.post('/api/v1/documents/signatures/register', payload);
```

---

### 5.3 Operación 3: Consulta Manual de Estado (`GET_HARDWARE_STATUS` o `PING`)
Permite al frontend solicitar el estado actual del lector y la tarjeta en cualquier instante:

```json
{
  "type": "GET_HARDWARE_STATUS",
  "requestId": "req-status-001"
}
```

Respuesta:
```json
{
  "type": "HARDWARE_STATUS_RESPONSE",
  "requestId": "req-status-001",
  "hardwareStatus": {
    "readerPresent": true,
    "cardPresent": true,
    "readerName": "Identiv uTrust 2700 R 0",
    "cardType": "DNIE_3_0",
    "isMock": false
  }
}
```

---

## 6. Manejo Estructurado de Errores

Cuando una operación falla o es abortada, el agente responde con un objeto de tipo `"ERROR"` asociado al `requestId`:

```json
{
  "type": "ERROR",
  "requestId": "req-auth-1002",
  "errorCode": "PIN_INCORRECT",
  "message": "El PIN ingresado es incorrecto. Quedan 2 intentos restantes.",
  "attemptsRemaining": 2
}
```

### Catálogo de Códigos de Error (`errorCode`)

| `errorCode` | Significado | Acción Sugerida en Frontend |
| :--- | :--- | :--- |
| **`PIN_INCORRECT`** | El usuario ingresó un PIN erróneo en el modal. `attemptsRemaining` indicará 1 o 2. | Mostrar alerta visual con los intentos que le restan al usuario antes del bloqueo. |
| **`PIN_LOCKED`** | Se agotaron los 3 intentos en el chip (`attemptsRemaining: 0`). | Informar al usuario que su DNIe fue bloqueado por RENIEC y debe usar su código PUK en una agencia. |
| **`CARD_NOT_PRESENT`** | No hay DNIe en la ranura o fue retirado durante la operación. | Solicitar al usuario que inserte su DNIe en el lector. |
| **`USER_CANCELLED`** | El usuario hizo clic en "Cancelar" o presionó Esc en el modal. | Finalizar la carga de la interfaz sin mostrar mensaje de error crítico. |
| **`OPERATION_IN_PROGRESS`** | Ya hay una solicitud de firma o modal abierto en curso. | Evitar clics dobles; esperar a que la operación activa termine. |
| **`CERTIFICATE_EXPIRED`** | El certificado X.509 de RENIEC en el chip ha caducado. | Alertar que debe renovar sus certificados de DNIe en RENIEC. |
| **`PKCS11_ERROR`** | Falla de lectura de hardware o driver de middleware no instalado. | Recomendar revisar la instalación del driver IDEMIA IDPlugClassic. |
| **`UNAUTHORIZED_ORIGIN`** | Origen web no autorizado por la política Zero Trust. | Verificar la configuración de `ALLOWED_ORIGINS` en el agente. |
| **`MALFORMED_REQUEST`** | Payload JSON no cumple con el esquema esperado. | Revisar los nombres y tipos de campos enviados. |

---

## 7. Cliente TypeScript Completo para Producción

Copia y pega este módulo en tu proyecto frontend (ej. `src/services/killAgentClient.ts`). Gestiona reconexión automática, cola de peticiones con promesas y tipado estricto.

```typescript
// src/services/killAgentClient.ts

export type CardType = 'NONE' | 'DNIE_2_0' | 'DNIE_3_0' | 'UNKNOWN';

export interface HardwareStatus {
  readerPresent: boolean;
  cardPresent: boolean;
  readerName: string | null;
  cardType: CardType;
  isMock: boolean;
}

export type ErrorCode =
  | 'PIN_INCORRECT'
  | 'PIN_LOCKED'
  | 'CARD_NOT_PRESENT'
  | 'USER_CANCELLED'
  | 'PKCS11_ERROR'
  | 'CERTIFICATE_EXPIRED'
  | 'OPERATION_IN_PROGRESS'
  | 'UNAUTHORIZED_ORIGIN'
  | 'MALFORMED_REQUEST'
  | 'INTERNAL_SERVER_ERROR';

export interface KillAgentError {
  type: 'ERROR';
  requestId: string;
  errorCode: ErrorCode;
  message: string;
  attemptsRemaining?: number | null;
}

export interface AuthChallengePayload {
  nonce: string;
  signedNonce: string;
  clientCertificatePem: string;
  wsConnectionId: string;
  metadata: {
    dni: string;
    fullName: string;
    certificateSerialNumber: string;
    validTo: string;
  };
}

export interface DocumentDigestPayload {
  slotId: string;
  certificateDni: string;
  documentHash: string;
  signatureValue: string;
  signerSubjectDn: string;
  certificateSerialNumber: string;
  clientCertificatePem: string;
}

export type KillAgentEventCallback = {
  onStatusChange?: (status: HardwareStatus) => void;
  onCardInserted?: (readerName: string) => void;
  onCardRemoved?: () => void;
  onConnected?: (connectionId: string, status: HardwareStatus) => void;
  onDisconnected?: () => void;
};

export class KillAgentClient {
  private ws: WebSocket | null = null;
  private pendingRequests = new Map<string, { resolve: (val: any) => void; reject: (err: any) => void; timer: any }>();
  private listeners: KillAgentEventCallback = {};
  private currentHardwareStatus: HardwareStatus = {
    readerPresent: false,
    cardPresent: false,
    readerName: null,
    cardType: 'NONE',
    isMock: false
  };
  private isExplicitlyClosed = false;
  private reconnectAttempts = 0;
  private readonly endpoint: string;

  constructor(endpoint = 'ws://127.0.0.1:3000') {
    this.endpoint = endpoint;
  }

  public setListeners(listeners: KillAgentEventCallback) {
    this.listeners = { ...this.listeners, ...listeners };
  }

  public getHardwareStatus(): HardwareStatus {
    return this.currentHardwareStatus;
  }

  public isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  public connect(): Promise<HardwareStatus> {
    this.isExplicitlyClosed = false;

    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.endpoint);
      } catch (err) {
        return reject(err);
      }

      const connectionTimeout = setTimeout(() => {
        if (this.ws && this.ws.readyState !== WebSocket.OPEN) {
          this.ws.close();
          reject(new Error("Timeout al conectar con KILLAgent. ¿Está el daemon ejecutándose?"));
        }
      }, 4000);

      this.ws.onopen = () => {
        clearTimeout(connectionTimeout);
        this.reconnectAttempts = 0;
      };

      this.ws.onclose = () => {
        clearTimeout(connectionTimeout);
        this.currentHardwareStatus = {
          readerPresent: false,
          cardPresent: false,
          readerName: null,
          cardType: 'NONE',
          isMock: false
        };
        this.rejectAllPending(new Error("Conexión con KILLAgent cerrada."));
        this.listeners.onDisconnected?.();

        if (!this.isExplicitlyClosed) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = (evt) => {
        clearTimeout(connectionTimeout);
      };

      this.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          this.handleIncomingMessage(msg, resolve);
        } catch (e) {
          console.error("[KILLAgentClient] Error al procesar mensaje entrante:", e);
        }
      };
    });
  }

  public disconnect() {
    this.isExplicitlyClosed = true;
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  /**
   * Solicita la firma de un reto de identidad (Autenticación / Login Fase 2)
   */
  public async signAuthChallenge(nonce: string, timeoutMs = 60000): Promise<AuthChallengePayload> {
    const requestId = `req-auth-${crypto.randomUUID()}`;
    const response = await this.sendRequest(
      { type: 'SIGN_AUTH_CHALLENGE', requestId, nonce },
      requestId,
      timeoutMs
    );
    return response.payload as AuthChallengePayload;
  }

  /**
   * Solicita la firma de un digest SHA-256 de documento (PAdES-LTV)
   */
  public async signDocumentDigest(
    params: { slotId: string; documentHash: string; documentTitle: string; signerRole?: string },
    timeoutMs = 90000
  ): Promise<DocumentDigestPayload> {
    const requestId = `req-doc-${crypto.randomUUID()}`;
    const response = await this.sendRequest(
      {
        type: 'SIGN_DOCUMENT_DIGEST',
        requestId,
        slotId: params.slotId,
        documentHash: params.documentHash,
        documentTitle: params.documentTitle,
        signerRole: params.signerRole || 'SIGNER'
      },
      requestId,
      timeoutMs
    );
    return response.payload as DocumentDigestPayload;
  }

  private sendRequest(payload: any, requestId: string, timeoutMs: number): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.isConnected()) {
        return reject(new Error("KILLAgent no está conectado en este momento."));
      }

      const timer = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        reject(new Error("Tiempo de espera agotado para la respuesta de KILLAgent."));
      }, timeoutMs);

      this.pendingRequests.set(requestId, { resolve, reject, timer });
      this.ws!.send(JSON.stringify(payload));
    });
  }

  private handleIncomingMessage(msg: any, initialConnectResolve?: (status: HardwareStatus) => void) {
    // 1. Mensaje de bienvenida inicial
    if (msg.type === 'CONNECTION_ESTABLISHED') {
      this.currentHardwareStatus = msg.hardwareStatus;
      this.listeners.onConnected?.(msg.wsConnectionId, msg.hardwareStatus);
      this.listeners.onStatusChange?.(msg.hardwareStatus);
      if (initialConnectResolve) {
        initialConnectResolve(msg.hardwareStatus);
      }
      return;
    }

    // 2. Eventos Push de Hardware (Kill-Switch)
    if (msg.type === 'CARD_REMOVED') {
      this.currentHardwareStatus.cardPresent = false;
      this.currentHardwareStatus.cardType = 'NONE';
      this.listeners.onCardRemoved?.();
      this.listeners.onStatusChange?.(this.currentHardwareStatus);
      return;
    }

    if (msg.type === 'CARD_INSERTED') {
      this.currentHardwareStatus.cardPresent = true;
      this.listeners.onCardInserted?.(msg.readerName);
      this.listeners.onStatusChange?.(this.currentHardwareStatus);
      return;
    }

    // 3. Manejo de Errores con requestId correlacionado
    if (msg.type === 'ERROR') {
      const pending = this.pendingRequests.get(msg.requestId);
      if (pending) {
        clearTimeout(pending.timer);
        this.pendingRequests.delete(msg.requestId);
        pending.reject(msg as KillAgentError);
      }
      return;
    }

    // 4. Respuestas exitosas a operaciones
    if (msg.requestId && this.pendingRequests.has(msg.requestId)) {
      const pending = this.pendingRequests.get(msg.requestId)!;
      clearTimeout(pending.timer);
      this.pendingRequests.delete(msg.requestId);
      pending.resolve(msg);
    }
  }

  private rejectAllPending(err: Error) {
    for (const [_, pending] of this.pendingRequests) {
      clearTimeout(pending.timer);
      pending.reject(err);
    }
    this.pendingRequests.clear();
  }

  private scheduleReconnect() {
    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), 10000);
    setTimeout(() => {
      if (!this.isExplicitlyClosed && !this.isConnected()) {
        this.connect().catch(() => {});
      }
    }, delay);
  }
}
```

---

## 8. Hook de React: `useKillAgent`

A continuación, una integración reactiva lista para componentes funcionales en React:

```tsx
// src/hooks/useKillAgent.ts
import { useEffect, useState, useCallback, useRef } from 'react';
import { KillAgentClient, HardwareStatus, KillAgentError } from '../services/killAgentClient';

export function useKillAgent(endpoint?: string) {
  const [isConnected, setIsConnected] = useState(false);
  const [hardwareStatus, setHardwareStatus] = useState<HardwareStatus>({
    readerPresent: false,
    cardPresent: false,
    readerName: null,
    cardType: 'NONE',
    isMock: false
  });
  const [lastError, setLastError] = useState<KillAgentError | null>(null);

  const clientRef = useRef<KillAgentClient | null>(null);

  if (!clientRef.current) {
    clientRef.current = new KillAgentClient(endpoint);
  }

  useEffect(() => {
    const client = clientRef.current!;

    client.setListeners({
      onConnected: () => setIsConnected(true),
      onDisconnected: () => setIsConnected(false),
      onStatusChange: (status) => setHardwareStatus({ ...status }),
      onCardRemoved: () => {
        // Kill-switch: opcionalmente disparar aquí logout o toast
      }
    });

    client.connect().catch((err) => {
      console.warn("KILLAgent no disponible en inicio:", err.message);
    });

    return () => {
      client.disconnect();
    };
  }, []);

  const signAuth = useCallback(async (nonce: string) => {
    setLastError(null);
    try {
      return await clientRef.current!.signAuthChallenge(nonce);
    } catch (err: any) {
      setLastError(err);
      throw err;
    }
  }, []);

  const signDocument = useCallback(async (slotId: string, documentHash: string, documentTitle: string, role?: string) => {
    setLastError(null);
    try {
      return await clientRef.current!.signDocumentDigest({
        slotId,
        documentHash,
        documentTitle,
        signerRole: role
      });
    } catch (err: any) {
      setLastError(err);
      throw err;
    }
  }, []);

  return {
    isConnected,
    hardwareStatus,
    isCardReady: isConnected && hardwareStatus.cardPresent,
    lastError,
    signAuth,
    signDocument
  };
}
```

### Ejemplo de Uso en Componente de Firma:
```tsx
import React, { useState } from 'react';
import { useKillAgent } from '../hooks/useKillAgent';

export function DocumentSigningButton({ documentId, docHash, docTitle }: any) {
  const { isConnected, isCardReady, signDocument, lastError } = useKillAgent();
  const [signing, setSigning] = useState(false);

  const handleSign = async () => {
    setSigning(true);
    try {
      const result = await signDocument("slot-123", docHash, docTitle, "ABOGADO");
      alert(`¡Documento firmado con éxito por DNI: ${result.certificateDni}!`);
      // Enviar result a API Ch'aska...
    } catch (err: any) {
      if (err.errorCode === 'USER_CANCELLED') {
        console.log("Firma cancelada por el usuario.");
      } else {
        alert(`Error: ${err.message}`);
      }
    } finally {
      setSigning(false);
    }
  };

  if (!isConnected) {
    return <div className="badge badge-warning">Esperando agente de escritorio KILLAgent...</div>;
  }

  if (!isCardReady) {
    return <div className="badge badge-danger">Inserte su DNIe en el lector USB para firmar</div>;
  }

  return (
    <button onClick={handleSign} disabled={signing} className="btn btn-primary">
      {signing ? "Confirmando en ventana de seguridad..." : "Firmar con DNIe"}
    </button>
  );
}
```


