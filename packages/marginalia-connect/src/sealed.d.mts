import type { KeyObject } from 'node:crypto';
import type { Buffer } from 'node:buffer';

export declare function b64url(bytes: Uint8Array): string;
export declare function fromB64url(text: string): Buffer;
export declare function privateKeyFromRaw(raw: Uint8Array): KeyObject;
export declare function rawPublicKey(key: KeyObject): Buffer;

export interface InnerRequest {
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
  queued?: boolean;
  ts?: number;
}
export interface InnerReply { status: number; contentType?: string; body?: string }
export declare function sealRequest(
  devicePublicKey: Uint8Array,
  request: InnerRequest,
  fixed?: { ephemeralPrivate?: Uint8Array; iv?: Uint8Array },
): { body: string; openReply(text: string): InnerReply };
export declare function openRequest(devicePrivateRaw: Uint8Array, text: string): {
  request: Required<InnerRequest>;
  sealReply(reply: InnerReply): string;
};
export declare function safetyCode(publicKey: Uint8Array): string;
export declare function parseAddress(address: string): {
  base: string;
  tunnel: string;
  devicePublicKey: Buffer;
};
