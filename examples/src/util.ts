import { CheckResource, InstagramCheckCertificateData } from '@appliedblockchain/silentdata-node'
import secp256k1 from 'secp256k1'
import create from 'keccak'

type CertificateDataOutput = Omit<
  InstagramCheckCertificateData,
  'check_hash' | 'certificate_hash' | 'initiator_pkey'
> & {
  certificate_hash: string
  check_hash: string
  initiator_pkey: string
}

export function parseCertificateData(check: CheckResource): CertificateDataOutput | null {
  const certificateData = check.getCertificateDataAsJSON()
  if (!certificateData) {
    return null
  }
  return {
    check_hash: '0x' + certificateData.check_hash.toString('hex'),
    certificate_hash: '0x' + certificateData.certificate_hash.toString('hex'),
    id: certificateData.id,
    initiator_pkey: '0x' + certificateData.initiator_pkey.toString('hex'),
    ig_account_type: (certificateData as InstagramCheckCertificateData).ig_account_type,
    ig_username: (certificateData as InstagramCheckCertificateData).ig_username,
    timestamp: certificateData.timestamp,
  }
}

function addRecoveryId(signatureHex: string, messageHex?: string, signingKeyHex?: string): string {
  if (!messageHex || !signingKeyHex) {
    return 'Invalid signature'
  }
  const recoveryIds = ['00', '01', '02', '03']
  const signature = Buffer.from(signatureHex, 'hex')
  const message = Buffer.from(messageHex, 'hex')
  const keccak = create('keccak256')
  const messageHash = keccak.update(message).digest()
  const signingKey = Buffer.from(signingKeyHex, 'hex')
  for (let i = 0; i < 4; i++) {
    const recoveredKey = secp256k1.ecdsaRecover(signature, i, messageHash, true)
    if (Buffer.compare(signingKey, Buffer.from(recoveredKey)) === 0) {
      return signatureHex + recoveryIds[i]
    }
  }
  return 'Invalid signature'
}

export function printCertificateData(check: CheckResource): void {
  console.log('Proof certificate:')
  console.log(parseCertificateData(check))
  console.log('Proof verification:')
  for (const [key, value] of Object.entries(check.data)) {
    if (key === 'signature' && typeof value === 'string') {
      console.log(key + ' = ' + addRecoveryId(value, check.data.rawData, check.data.signingKey))
    } else {
      console.log(key + ' = ' + value)
    }
  }
}
