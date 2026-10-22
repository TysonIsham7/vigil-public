export interface DerField {
  tag: number;
  offset: number;
  start: number;
  end: number;
}

export interface CertificateFields {
  spki: Buffer;
  notBefore: number;
  notAfter: number;
  selfSigned: boolean;
  sanDns: string[];
  commonName: string | null;
}

export function readTLV(buf: Buffer, offset: number): DerField | null;

export function parseCertificate(der: Uint8Array): CertificateFields | null;
